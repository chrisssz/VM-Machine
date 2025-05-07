use std::io::{self, Write};
use std::convert::TryInto;

/// Sign‑extend a u32 `value` whose low `bits` bits are the real data.
pub fn sign_extend(value: u32, bits: u8) -> i32 {
    let shift = 32 - bits as i32;
    ((value << shift) as i32) >> shift
}

/// Pop a 4‑byte little‑endian i32 from the stack and advance SP upward.
pub fn pop_i32(stack: &[u8; 4096], sp: &mut usize) -> i32 {
    let raw = &stack[*sp..*sp + 4];
    let v = i32::from_le_bytes(raw.try_into().unwrap());
    *sp = (*sp + 4).min(4096);
    v
}

/// Push a 4‑byte little‑endian i32 onto the stack, moving SP downward.
pub fn push(stack: &mut [u8; 4096], sp: &mut usize, v: i32) {
    let bytes = v.to_le_bytes();
    *sp = sp.saturating_sub(4);
    stack[*sp..*sp + 4].copy_from_slice(&bytes);
}

/// Execute the single instruction at PC.  
/// Returns `Some(exit_code)` if an exit occurred; otherwise `None`.
pub fn execute(
    stack: &mut [u8; 4096],
    sp: &mut usize,
    pc: &mut isize,
) -> Option<i32> {
    let byte_addr = (*pc * 4) as usize;
    let instr = u32::from_le_bytes(
        stack[byte_addr..byte_addr + 4]
            .try_into()
            .unwrap(),
    );
    let opcode = (instr >> 28) as u8;

    match opcode {
        0 => {
            // misc: exit, swap, nop, input, stinput, debug
            let sub = ((instr << 4) >> 28) as u8;
            match sub {
                0 => {
                    // exit [code]
                    let code = (instr & 0xF) as i32;
                    return Some(code);
                }
                1 => {
                    // swap [from][to]
                    let raw_from = (instr >> 12) & 0xFFF;
                    let raw_to   = instr & 0xFFF;
                    let off_from = (sign_extend(raw_from, 12) << 2) as isize;
                    let off_to   = (sign_extend(raw_to,   12) << 2) as isize;
                    let a = (*sp as isize + off_from) as usize;
                    let b = (*sp as isize + off_to)   as usize;
                    for i in 0..4 {
                        stack.swap(a + i, b + i);
                    }
                }
                2 => {
                    // nop
                }
                4 => {
                    // input → push 4‑byte int
                    let mut line = String::new();
                    io::stdin().read_line(&mut line).unwrap();
                    let s = line.trim();
                    let val = if s.to_lowercase().starts_with("0x") {
                        i32::from_str_radix(&s[2..], 16).unwrap()
                    } else if s.to_lowercase().starts_with("0b") {
                        i32::from_str_radix(&s[2..], 2).unwrap()
                    } else {
                        s.parse::<i32>().unwrap()
                    };
                    *sp -= 4;
                    stack[*sp..*sp + 4].copy_from_slice(&val.to_le_bytes());
                }
                5 => {
                    // stinput [max_chars] → push bytes
                    let mut cap = ((instr << 8) >> 8) as usize;
                    if cap == 0 {
                        cap = 0x00FF_FFFF;
                    }
                    let mut line = String::new();
                    io::stdin().read_line(&mut line).unwrap();
                    let trimmed = line.trim();
                    let s = if trimmed.is_empty() { "\0" } else { trimmed };
                    let data: Vec<u8> =
                        s.chars().take(cap).map(|c| c as u8).collect();
                    *sp -= data.len();
                    stack[*sp..*sp + data.len()].copy_from_slice(&data);
                }
                15 => {
                    // debug [value]
                    let imm24 = instr & 0x00FF_FFFF;
                    let pc_b  = (*pc * 4) as u32;
                    let sp_b  = *sp as u32;
                    println!(
                        "DEBUG: PC={:#06x}, SP={:#06x}, instr_val={:#010x}",
                        pc_b, sp_b, imm24
                    );
                }
                _ => eprintln!("error: impossible subcode {} for opcode 0", sub),
            }
            *pc += 1;
        }

        1 => {
            // pop [offset]
            let offs = (instr & 0x0FFF_FFFF) as usize;
            *sp = (*sp + offs).min(4096);
            *pc += 1;
        }

        2 => {
            // binary arithmetic
            let kind = ((instr >> 24) & 0xF) as u8;
            let r = pop_i32(stack, sp);
            let l = pop_i32(stack, sp);
            let res = match kind {
                0  => l.wrapping_add(r),
                1  => l.wrapping_sub(r),
                2  => l.wrapping_mul(r),
                3  => if r != 0 { l / r } else { 0 },
                4  => if r != 0 { l % r } else { 0 },
                5  => l & r,
                6  => l | r,
                7  => l ^ r,
                8  => l.wrapping_shl(r as u32),
                9  => ((l as u32).wrapping_shr(r as u32)) as i32,
                11 => l.wrapping_shr(r as u32),
                _  => 0,
            };
            push(stack, sp, res);
            *pc += 1;
        }

        3 => {
            // unary arithmetic
            let kind = ((instr >> 24) & 0xF) as u8;
            let v = pop_i32(stack, sp);
            let res = match kind {
                0 => -v,
                1 => !v,
                _ => v,
            };
            push(stack, sp, res);
            *pc += 1;
        }

        4 => {
            // stprint [offset]
            let raw = (instr >> 2) & 0x03FF_FFFF;
            let off = (sign_extend(raw, 26) << 2) as isize;
            let mut addr = (*sp as isize + off) as usize;
            while addr < 4096 {
                let b = stack[addr];
                addr += 1;
                if b == 0 { break; }
                if b == 1 { continue; }
                print!("{}", b as char);
            }
            io::stdout().flush().unwrap();
            *pc += 1;
        }

        5 => {
            // call <label>
            let raw   = (instr >> 2) & 0x03FF_FFFF;
            let delta = sign_extend(raw, 26) as isize;
            let ret   = ((*pc + 1) * 4) as i32;
            push(stack, sp, ret);
            *pc = *pc + delta;
        }

        6 => {
            // return [offset]
            let off_ins = ((instr >> 2) & 0x03FF_FFFF) as usize;
            *sp = (*sp + off_ins * 4).min(4096);
            let ret = pop_i32(stack, sp) as isize;
            *pc = ret / 4;
        }

        7 => {
            // goto <label>
            let raw   = (instr >> 2) & 0x03FF_FFFF;
            let delta = sign_extend(raw, 26) as isize;
            *pc = *pc + delta;
        }

        8 => {
            // if<cond> <label>
            let cond  = ((instr >> 25) & 0x7) as u8;
            let imm   = (instr >> 2) & 0x007F_FFFF;
            let delta = sign_extend(imm, 23) as isize;
            let right = i32::from_le_bytes(
                stack[*sp .. *sp + 4].try_into().unwrap()
            );
            let left  = i32::from_le_bytes(
                stack[*sp + 4 .. *sp + 8].try_into().unwrap()
            );
            let take = match cond {
                0 => left == right,
                1 => left != right,
                2 => left <  right,
                3 => left >  right,
                4 => left <= right,
                5 => left >= right,
                _ => false,
            };
            *pc = if take { *pc + delta } else { *pc + 1 };
        }

        9 => {
            // unary if<cond> <label>
            let cond   = ((instr << 5) >> 30) as u8;
            let offset = (((instr << 7) as i32) >> 7) as isize;
            let mut b = [0u8; 4];
            for i in 0..4 {
                b[i] = *stack.get(*sp + i).unwrap_or(&0);
            }
            let val = i32::from_le_bytes(b);
            let take = match cond {
                0 => val == 0,
                1 => val != 0,
                2 => val <  0,
                3 => val >= 0,
                _ => false,
            };
            *pc = if take { *pc + (offset / 4) } else { *pc + 1 };
        }

        12 => {
            // dup [offset]
            let off = ((instr << 4) >> 4) as usize;
            *sp = (*sp).saturating_sub(4);
            let mut buf = [0u8; 4];
            buf.copy_from_slice(
                &stack[*sp + 4 + off .. *sp + 8 + off]
            );
            stack[*sp .. *sp + 4].copy_from_slice(&buf);
            *pc += 1;
        }

        13 => {
            // print[h|o|b] [offset]
            let raw = (instr >> 2) & 0x03FF_FFFF;
            let off = (sign_extend(raw, 26) << 2) as isize;
            let addr = (*sp as isize + off) as usize;
            let val  = i32::from_le_bytes(
                stack[addr .. addr + 4].try_into().unwrap()
            );
            let fmt = (instr & 0x3) as u8;
            match fmt {
                0 => println!("{}",      val),
                1 => println!("0x{:x}", val),
                2 => println!("0b{:b}", val),
                3 => println!("0o{:o}", val),
                _ => unreachable!(),
            }
            *pc += 1;
        }

        14 => {
            // dump
            let mut addr = *sp;
            while addr < 4096 {
                let word = i32::from_le_bytes(
                    stack[addr .. addr + 4].try_into().unwrap()
                );
                println!("{:04x}: {:08x}", addr, word);
                addr += 4;
            }
            *pc += 1;
        }

        15 => {
            // push [value]
            let value = ((instr << 4) as i32) >> 4;
            *sp = (*sp).saturating_sub(4);
            stack[*sp .. *sp + 4].copy_from_slice(&value.to_le_bytes());
            *pc += 1;
        }

        _ => {
            eprintln!("error: invalid opcode {}", opcode);
            return Some(1);
        }
    }

    None
}

