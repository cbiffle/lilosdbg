use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::Ordering;
use std::{fmt::Display, io::BufRead};

use anyhow::{Result, bail};
use clap::Parser;
use debugdb::{EntityId, VarId};
use debugdb::value::{ValueWithDb, self};
use object::{Object, ObjectSegment};
use rangemap::{RangeMap, RangeInclusiveMap};

use debugdb::{Type, Encoding, TypeId, Struct, Member, DebugDb, Enum, VariantShape, value::Value};
use debugdb::load::{Load, ImgMachine, Machine, LoadError};
use regex::Regex;
use ansi_term::Colour;

#[derive(Debug, Parser)]
struct Lildb {
    filename: std::path::PathBuf,
}

fn main() -> Result<()> {
    let args = Lildb::parse();

    let everything;
    let mut segments = RangeInclusiveMap::new();
    let mut registers = BTreeMap::new();

    let input = std::fs::File::open(&args.filename)?;

    // First, try loading as a snapshot.
    if let Ok(mut snap) = lilosdbg::load_snapshot(input) {
        let elf_files = snap.elf_files().collect::<Vec<_>>();
        if elf_files.len() == 0 {
            bail!("snapshot does not contain ELF file.");
        } else if elf_files.len() > 1 {
            bail!("snapshot contains too many ELF files.");
        }

        let mut image = vec![];
        snap.file_by_index(elf_files[0].0).read_to_end(&mut image)?;
        let object = object::File::parse(&*image)?;
        for seg in object.segments() {
            if seg.size() == 0 {
                continue;
            }
            segments.insert(
                seg.address()..=seg.address() + (seg.size() - 1),
                seg.data()?.to_vec(),
            );
        }
        everything = debugdb::parse_file(&object)?;

        // TODO ugh, zip wants &mut to do reads, making it damn hard to iterate
        // over the snapshot... this crate might not be the right crate
        let range_copy = snap.ranges().map(|(r, f)| (r, f.index)).collect::<Vec<_>>();
        for (addrs, index) in range_copy {
            let mut image = vec![];
            snap.file_by_index(index).read_to_end(&mut image)?;
            segments.insert(addrs, image);
        }

        for (i, v) in snap.registers() {
            registers.insert(i, v);
        }
    } else {
        let buffer = std::fs::read(args.filename)?;
        let object = object::File::parse(&*buffer)?;
        for seg in object.segments() {
            if seg.size() == 0 {
                continue;
            }
            segments.insert(
                seg.address()..=seg.address() + (seg.size() - 1),
                seg.data()?.to_vec(),
            );
        }
        everything = debugdb::parse_file(&object)?;
    }

    println!("Loaded; {} types found in program.", everything.type_count());
    println!("To quit: ^D or exit");

    let mut rl = rustyline::Editor::<(), _>::new()?;
    let prompt = ansi_term::Colour::Green.paint(">> ").to_string();
    let mut ctx = Ctx {
        segments,
        registers,
    };
    'lineloop:
    loop {
        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                let (cmd, rest) = line.split_once(char::is_whitespace)
                    .unwrap_or((line, ""));
                if line.is_empty() {
                    continue 'lineloop;
                }

                rl.add_history_entry(line)?;

                match cmd {
                    "exit" => break,
                    "help" => {
                        println!("commands:");
                        let name_len = COMMANDS.iter()
                            .map(|(name, _, _)| name.len())
                            .max()
                            .unwrap_or(12);
                        for (name, _, desc) in COMMANDS {
                            println!("{:name_len$} {}", name, desc);
                        }
                    }
                    _ => {
                        for (name, imp, _) in COMMANDS {
                            if *name == cmd {
                                imp(&everything, &mut ctx, rest);
                                continue 'lineloop;
                            }
                        }
                        println!("unknown command: {}", cmd);
                        println!("for help, try: help");
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(e) => {
                println!("{:?}", e);
                break;
            }
        }
    }

    Ok(())
}

struct Goff(gimli::UnitSectionOffset);

impl std::fmt::Display for Goff {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            gimli::UnitSectionOffset::DebugInfoOffset(gimli::DebugInfoOffset(x)) => {
                write!(f, "<.debug_info+0x{:08x}>", x)
            }
            gimli::UnitSectionOffset::DebugTypesOffset(gimli::DebugTypesOffset(x)) => {
                write!(f, "<.debug_types+0x{:08x}>", x)
            }
        }
    }
}

struct NamedGoff<'a>(&'a debugdb::DebugDb, TypeId);

impl std::fmt::Display for NamedGoff<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let bold = ansi_term::Style::new().bold();
        let dim = ansi_term::Style::new().dimmed();

        let n = if let Some(name) = self.0.type_name(self.1) {
            name
        } else {
            "<anonymous type>".into()
        };

        write!(f, "{}", bold.paint(n))?;
        match self.1.0 {
            gimli::UnitSectionOffset::DebugInfoOffset(gimli::DebugInfoOffset(x)) => {
                write!(f, " {}<.debug_info+0x{:08x}>{}", dim.prefix(), x, dim.suffix())
            }
            gimli::UnitSectionOffset::DebugTypesOffset(gimli::DebugTypesOffset(x)) => {
                write!(f, " {}<.debug_types+0x{:08x}>{}", dim.prefix(), x, dim.suffix())
            }
        }
    }
}

struct Ctx {
    segments: RangeInclusiveMap<u64, Vec<u8>>,
    registers: BTreeMap<u16, u64>,
}

impl Ctx {
    pub fn program_counter(&self) -> Option<u64> {
        // TODO very ARM-specific!
        self.registers.get(&15).copied()
    }
    pub fn register(&self, index: u16) -> Option<u64> {
        self.registers.get(&index).copied()
    }
}

type Command = fn(&debugdb::DebugDb, &mut Ctx, &str);

static COMMANDS: &[(&str, Command, &str)] = &[
    ("list", cmd_list, "print names of ALL types, or types containing a string"),
    ("info", cmd_info, "print a summary of a type"),
    ("load", cmd_load, "loads additional segment data"),
    ("def", cmd_def, "print a type as a pseudo-Rust definition"),
    ("sizeof", cmd_sizeof, "print size of type in bytes"),
    ("alignof", cmd_alignof, "print alignment of type in bytes"),
    ("addr", cmd_addr, "look up information about an address"),
    ("addr2line", cmd_addr2line, "look up line number information"),
    ("addr2stack", cmd_addr2stack, "display inlined stack frames"),
    ("vars", cmd_vars, "list static variables"),
    ("var", cmd_var, "get info on a static variable"),
    ("unwind", cmd_unwind, "get unwind info for an address"),
    ("decode", cmd_decode, "interpret RAM/ROM as a type"),
    ("decode-async", cmd_decode_async, "interpret RAM/ROM as a suspended future"),
    ("decode-blob", cmd_decode_blob, "attempt to interpret bytes as a type"),
    ("decode-async-blob", cmd_decode_async_blob, "attempt to interpret bytes as a suspended future"),

    ("tasks", cmd_tasks, "print lilos task status"),
    ("time", cmd_time, "print current lilos tick time"),
    ("stack", cmd_stack, "print information about stack usage"),
    ("reg", cmd_reg, "register access"),
];

fn cmd_list(
    db: &debugdb::DebugDb,
    _ctx: &mut Ctx,
    args: &str,
) {
    // We're gonna make a copy to sort it, because alphabetical order seems
    // polite.
    let mut types_copy = db.canonical_types()
        .filter(|(goff, _ty)| {
            if !args.is_empty() {
                if let Some(name) = db.type_name(*goff) {
                    return name.contains(args);
                } else {
                    return false;
                }
            }
            true
        })
        .collect::<Vec<_>>();

    types_copy.sort_by_key(|(goff, _ty)| db.type_name(*goff));

    for (goff, ty) in types_copy {
        let kind = match ty {
            Type::Base(_) => "base",
            Type::Struct(_) => "struct",
            Type::Enum(_) => "enum",
            Type::CEnum(_) => "c-enum",
            Type::Array(_) => "array",
            Type::Pointer(_) => "ptr",
            Type::Union(_) => "union",
            Type::Subroutine(_) => "subr",
            Type::Unresolved(_) => "missing",
        };

        let aliases = db.aliases_of_type(goff);
        if let Some(aliases) = aliases {
            println!("{:6} {} ({} aliases)", kind, NamedGoff(db, goff), aliases.len());
        } else {
            println!("{:6} {}", kind, NamedGoff(db, goff));
        }
    }
}

fn parse_type_name(s: &str) -> Option<ParsedTypeName<'_>> {
    if s.starts_with("<.debug_") && s.ends_with('>') {
        // Try parsing as a debug section reference.
        let rest = &s[8..];
        return if rest.starts_with("info+0x") {
            let num = &rest[7..rest.len() - 1];
            if let Ok(n) = usize::from_str_radix(num, 16) {
                Some(ParsedTypeName::Goff(TypeId(gimli::DebugInfoOffset(n).into())))
            } else {
                println!("can't parse {} as hex", num);
                None
            }
        } else if rest.starts_with("types+0x") {
            let num = &rest[8..rest.len() - 1];
            if let Ok(n) = usize::from_str_radix(num, 16) {
                Some(ParsedTypeName::Goff(TypeId(gimli::DebugTypesOffset(n).into())))
            } else {
                println!("can't parse {} as hex", num);
                None
            }
        } else {
            println!("bad offset reference: {}", s);
            None
        };
    }

    Some(ParsedTypeName::Name(s))
}

enum ParsedTypeName<'a> {
    Name(&'a str),
    Goff(TypeId),
}

fn simple_query_cmd(
    db: &debugdb::DebugDb,
    args: &str,
    q: fn(&debugdb::DebugDb, &debugdb::Type),
) {
    let type_name = args.trim();
    let types: Vec<_> = match parse_type_name(type_name) {
        None => return,
        Some(ParsedTypeName::Name(n)) => {
            db.types_by_name(n).collect()
        }
        Some(ParsedTypeName::Goff(o)) => {
            db.type_by_id(o).into_iter()
                .map(|t| (o, t))
                .collect()
        }
    };
    if type_name.starts_with("<.debug_") && type_name.ends_with('>') {
        // Try parsing as a debug section reference.
        let rest = &type_name[8..];
        if rest.starts_with("info+0x") {
        } else if rest.starts_with("types+0x") {
        }
    }

    let many = match types.len() {
        0 => {
            println!("{}", ansi_term::Colour::Red.paint("No types found."));
            return;
        }
        1 => false,
        n => {
            println!("{}{} types found with that name:",
                ansi_term::Color::Yellow.paint("note: "),
                n,
            );
            true
        }
    };

    for (goff, t) in types {
        if many { println!() }
        print!("{}: ", NamedGoff(db, goff));
        q(db, t);
    }
}

fn cmd_info(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    simple_query_cmd(db, args, |db, t| {
        match t {
            Type::Base(s) => {
                println!("base type");
                println!("- encoding: {:?}", s.encoding);
                println!("- byte size: {}", s.byte_size);
            }
            Type::Pointer(s) => {
                println!("pointer type");
                println!("- points to: {}", NamedGoff(db, s.type_id));
            }
            Type::Array(s) => {
                println!("array type");
                println!("- element type: {}", NamedGoff(db, s.element_type_id));
                println!("- lower bound: {}", s.lower_bound);
                if let Some(n) = s.count {
                    println!("- count: {}", n);
                } else {
                    println!("- size not given");
                }
            }
            Type::Struct(s) => {
                if s.tuple_like {
                    println!("struct type (tuple-like)");
                } else {
                    println!("struct type");
                }
                if let Some(z) = s.byte_size {
                    println!("- byte size: {z}");
                }
                if let Some(a) = s.alignment {
                    println!("- alignment: {}", a);
                } else {
                    println!("- not aligned");
                }
                if !s.template_type_parameters.is_empty() {
                    println!("- template type parameters:");
                    for ttp in &s.template_type_parameters {
                        println!("  - {} = {}", ttp.name, NamedGoff(db, ttp.type_id));
                    }
                }
                if !s.members.is_empty() {
                    println!("- members:");
                    for (i, mem) in s.members.iter().enumerate() {
                        if let Some(name) = &mem.name {
                            println!("  {i}. {name}: {}", NamedGoff(db, mem.type_id));
                        } else {
                            println!("  - <unnamed>: {}", NamedGoff(db, mem.type_id));
                        }
                        println!("    - offset: {} bytes", mem.location);
                        if let Some(s) = db.type_by_id(mem.type_id).unwrap().byte_size(db) {
                            println!("    - size: {} bytes", s);
                        }
                        if let Some(a) = mem.alignment {
                            println!("    - aligned: {} bytes", a);
                        }
                        if mem.artificial {
                            println!("    - artificial");
                        }
                    }
                } else {
                    println!("- no members");
                }

                struct_picture(db, s, db.pointer_size() as usize);
            }
            Type::Enum(s) => {
                println!("enum type");
                if let Some(z) = s.byte_size {
                    println!("- byte size: {z}");
                }
                if let Some(a) = s.alignment {
                    println!("- alignment: {}", a);
                } else {
                    println!("- not aligned");
                }
                if !s.template_type_parameters.is_empty() {
                    println!("- type parameters:");
                    for ttp in &s.template_type_parameters {
                        println!("  - {} = {}", ttp.name, NamedGoff(db, ttp.type_id));
                    }
                }

                match &s.shape {
                    debugdb::VariantShape::Zero => {
                        println!("- empty (uninhabited) enum");
                    }
                    debugdb::VariantShape::One(v) => {
                        println!("- single variant enum w/o discriminator");
                        println!("  - content type: {}", NamedGoff(db, v.member.type_id));
                        println!("  - offset: {} bytes", v.member.location);
                        if let Some(a) = v.member.alignment {
                            println!("  - aligned: {} bytes", a);
                        }
                        if !v.member.artificial {
                            println!("  - not artificial, oddly");
                        }
                    }
                    debugdb::VariantShape::Many { member, variants, .. }=> {
                        if let Some(dname) = db.type_name(member.type_id) {
                            println!("- {} variants discriminated by {} at offset {}", variants.len(), dname, member.location);
                        } else {
                            println!("- {} variants discriminated by an anonymous type at offset {}", variants.len(), member.location);
                        }
                        if !member.artificial {
                            println!("  - not artificial, oddly");
                        }
                        
                        // Print explicit values first
                        for (val, var) in variants {
                            if let Some(val) = val {
                                println!("- when discriminator == {}", val);
                                println!("  - contains type: {}", NamedGoff(db, var.member.type_id));
                                println!("  - at offset: {} bytes", var.member.location);
                                if let Some(a) = var.member.alignment {
                                    println!("  - aligned: {} bytes", a);
                                }
                            }
                        }
                        // Now, default.
                        for (val, var) in variants {
                            if val.is_none() {
                                println!("- any other discriminator value");
                                println!("  - contains type: {}", NamedGoff(db, var.member.type_id));
                                println!("  - at offset: {} bytes", var.member.location);
                                if let Some(a) = var.member.alignment {
                                    println!("  - aligned: {} bytes", a);
                                }
                            }
                        }
                    }
                }
                enum_picture(db, s, db.pointer_size() as usize);
            }
            Type::CEnum(s) => {
                println!("C-like enum type");
                println!("- byte size: {}", s.byte_size);
                if let Some(a) = s.alignment {
                    println!("- alignment: {a}");
                }
                println!("- {} values defined", s.enumerators.len());
                for e in s.enumerators.values() {
                    println!("  - {} = 0x{:x}", e.name, e.const_value);

                }
            }
            Type::Union(s) => {
                println!("union type");
                println!("- byte size: {}", s.byte_size);
                println!("- alignment: {}", s.alignment);
                if !s.template_type_parameters.is_empty() {
                    println!("- template type parameters:");
                    for ttp in &s.template_type_parameters {
                        println!("  - {} = {}", ttp.name, NamedGoff(db, ttp.type_id));
                    }
                }
                if !s.members.is_empty() {
                    println!("- members:");
                    for mem in &s.members {
                        if let Some(name) = &mem.name {
                            println!("  - {}: {}", name, NamedGoff(db, mem.type_id));
                        } else {
                            println!("  - <unnamed>: {}", NamedGoff(db, mem.type_id));
                        }
                        println!("    - offset: {} bytes", mem.location);
                        if let Some(a) = mem.alignment {
                            println!("    - aligned: {} bytes", a);
                        }
                        if mem.artificial {
                            println!("    - artificial");
                        }
                    }
                } else {
                    println!("- no members");
                }
            }
            Type::Subroutine(s) => {
                println!("subroutine type");
                if let Some(rt) = s.return_type_id {
                    println!("- return type: {}", NamedGoff(db, rt));
                }
                if !s.formal_parameters.is_empty() {
                    println!("- formal parameters:");
                    for &fp in &s.formal_parameters {
                        println!("  - {}", NamedGoff(db, fp));
                    }
                }
            }
            Type::Unresolved(_) => {
                println!("type not found in debug info!");
            }
        }
    })
}

fn cmd_sizeof(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    simple_query_cmd(db, args, |db, t| {
        if let Some(sz) = t.byte_size(db) {
            println!("{} bytes", sz);
        } else {
            println!("unsized");
        }
    })
}

fn cmd_alignof(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    simple_query_cmd(db, args, |db, t| {
        if let Some(sz) = t.alignment(db) {
            println!("align to {} bytes", sz);
        } else {
            println!("no alignment information");
        }
    })
}

fn cmd_def(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    simple_query_cmd(db, args, |db, t| {
        println!();
        match t {
            Type::Base(s) => {
                print!("type _ = ");
                match (s.encoding, s.byte_size) {
                    (_, 0) => print!("()"),
                    (Encoding::Unsigned, 1) => print!("u8"),
                    (Encoding::Unsigned, 2) => print!("u16"),
                    (Encoding::Unsigned, 4) => print!("u32"),
                    (Encoding::Unsigned, 8) => print!("u64"),
                    (Encoding::Unsigned, 16) => print!("u128"),
                    (Encoding::Signed, 1) => print!("i8"),
                    (Encoding::Signed, 2) => print!("i16"),
                    (Encoding::Signed, 4) => print!("i32"),
                    (Encoding::Signed, 8) => print!("i64"),
                    (Encoding::Signed, 16) => print!("i128"),
                    (Encoding::Float, 4) => print!("f32"),
                    (Encoding::Float, 8) => print!("f64"),
                    (Encoding::Boolean, 1) => print!("bool"),
                    (Encoding::UnsignedChar, 1) => print!("c_uchar"),
                    (Encoding::SignedChar, 1) => print!("c_schar"),
                    (Encoding::UtfChar, 4) => print!("char"),

                    (e, s) => print!("Unhandled{:?}{}", e, s),
                }
                println!(";");
            }
            Type::Pointer(_s) => {
                print!("type _ = {};", t.name(db));
            }
            Type::Array(s) => {
                let name = db.type_name(s.element_type_id).unwrap();
                if let Some(n) = s.count {
                    println!("[{}; {}]", name, n);
                } else {
                    println!("[{}]", name);
                }
            }
            Type::Struct(s) => {
                print!("struct {}", s.name);

                if !s.template_type_parameters.is_empty() {
                    print!("<");
                    for ttp in &s.template_type_parameters {
                        print!("{},", ttp.name);
                    }
                    print!(">");
                }
                
                if s.members.is_empty() {
                    println!(";");
                } else {
                    if s.tuple_like {
                        println!("(");
                        for mem in &s.members {
                            println!("    {},", db.type_name(mem.type_id).unwrap());
                        }
                        println!(");");
                    } else {
                        println!(" {{");
                        for mem in &s.members {
                            if let Some(name) = &mem.name {
                                println!("    {}: {},", name, db.type_name(mem.type_id).unwrap());
                            } else {
                                println!("    ANON: {},", db.type_name(mem.type_id).unwrap());
                            }
                        }
                        println!("}}");
                    }
                }
            }
            Type::Enum(s) => {
                print!("enum {}", s.name);
                if !s.template_type_parameters.is_empty() {
                    print!("<");
                    for ttp in &s.template_type_parameters {
                        print!("{}", ttp.name);
                    }
                    print!(">");
                }
                println!(" {{");

                match &s.shape {
                    debugdb::VariantShape::Zero => (),
                    debugdb::VariantShape::One(var) => {
                        if let Some(name) = &var.member.name {
                            print!("    {}", name);
                        } else {
                            print!("    ANON");
                        }

                        let mty = db.type_by_id(var.member.type_id)
                            .unwrap();
                        if let Type::Struct(s) = mty {
                            if !s.members.is_empty() {
                                if s.tuple_like {
                                    println!("(");
                                    for mem in &s.members {
                                        let mtn = db.type_name(mem.type_id).unwrap();
                                        println!("        {},", mtn);
                                    }
                                    print!("    )");
                                } else {
                                    println!(" {{");
                                    for mem in &s.members {
                                        let mtn = db.type_name(mem.type_id).unwrap();
                                        println!("        {}: {},", mem.name.as_ref().unwrap(), mtn);
                                    }
                                    print!("    }}");
                                }
                            }
                        } else {
                            print!("(unexpected weirdness)");
                        }

                        println!(",");
                    }
                    debugdb::VariantShape::Many { variants, .. }=> {
                        for var in variants.values() {
                            if let Some(name) = &var.member.name {
                                print!("    {}", name);
                            } else {
                                print!("    ANON");
                            }

                            let mty = db.type_by_id(var.member.type_id)
                                .unwrap();
                            if let Type::Struct(s) = mty {
                                if !s.members.is_empty() {
                                    if s.tuple_like {
                                        println!("(");
                                        for mem in &s.members {
                                            let mtn = db.type_name(mem.type_id).unwrap();
                                            println!("        {},", mtn);
                                        }
                                        print!("    )");
                                    } else {
                                        println!(" {{");
                                        for mem in &s.members {
                                            let mtn = db.type_name(mem.type_id).unwrap();
                                            println!("        {}: {},", mem.name.as_ref().unwrap(), mtn);
                                        }
                                        print!("    }}");
                                    }
                                }
                            } else {
                                print!("(unexpected weirdness)");
                            }

                            println!(",");
                        }
                    }
                }
                println!("}}");

            }
            Type::CEnum(s) => {
                println!("enum {} {{", s.name);
                for (val, e) in &s.enumerators {
                    println!("    {} = 0x{:x},", e.name, val);
                }
                println!("}}");
            }
            Type::Union(s) => {
                print!("union {}", s.name);

                if !s.template_type_parameters.is_empty() {
                    print!("<");
                    for ttp in &s.template_type_parameters {
                        print!("{},", ttp.name);
                    }
                    print!(">");
                }

                println!(" {{");
                for mem in &s.members {
                    if let Some(name) = &mem.name {
                        println!("    {}: {},", name, db.type_name(mem.type_id).unwrap());
                    } else {
                        println!("    ANON: {},", db.type_name(mem.type_id).unwrap());
                    }
                }
                println!("}}");
            }
            Type::Subroutine(s) => {
                println!("fn(");
                for &p in &s.formal_parameters {
                    println!("    {},", db.type_name(p).unwrap());
                }
                if let Some(rt) = s.return_type_id {
                    println!(") -> {} {{", db.type_name(rt).unwrap());
                } else {
                    println!(") {{");
                }
                println!("    // code goes here");
                println!("    // (this is a subroutine type, _not_ a fn ptr)");
                println!("    unimplemented!();");
                println!("}}");
            }
            Type::Unresolved(_) => {
                println!("(type not found in debug info!)");
            }
        }
    })
}

fn cmd_addr2line(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    let addr = if args.starts_with("0x") {
        if let Ok(a) = u64::from_str_radix(&args[2..], 16) {
            a
        } else {
            println!("can't parse {} as an address", args);
            return;
        }
    } else if let Ok(a) = args.parse::<u64>() {
        a
    } else {
        println!("can't parse {} as an address", args);
        return;
    };

    if let Some(row) = db.lookup_line_row(addr) {
        print!("{}:", row.file);
        if let Some(line) = row.line {
            print!("{}:", line);
        } else {
            print!("?:");
        }
        if let Some(col) = row.column {
            print!("{}", col);
        } else {
            print!("?");
        }
        println!();
    } else {
        println!("no line number information available for address");
    }
}

fn cmd_addr2stack(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    let addr = if args.starts_with("0x") {
        if let Ok(a) = u64::from_str_radix(&args[2..], 16) {
            a
        } else {
            println!("can't parse {} as an address", args);
            return;
        }
    } else if let Ok(a) = args.parse::<u64>() {
        a
    } else {
        println!("can't parse {} as an address", args);
        return;
    };

    let bold = ansi_term::Style::new().bold();
    let dim = ansi_term::Style::new().dimmed();

    match db.static_stack_for_pc(addr) {
        Ok(Some(trc)) => {
            println!("Static stack trace fragment for address 0x{:x}", addr);
            println!("(innermost / most recent first)");
            for (i, record) in trc.iter().rev().enumerate() {
                let subp = db.subprogram_by_id(record.subprogram).unwrap();

                print!("{:4}   ", i);
                if let Some(n) = &subp.name {
                    println!("{}", bold.paint(n));
                } else {
                    println!("{}", bold.paint("<unknown-subprogram>"));
                }
                print!("{}", dim.prefix());
                print!("    {}:", record.file);
                if let Some(line) = record.line {
                    print!("{}:", line);
                } else {
                    print!("?:");
                }
                if let Some(col) = record.column {
                    print!("{}", col);
                } else {
                    print!("?");
                }
                print!("{}", dim.suffix());
                println!();
            }
        }
        Ok(None) => {
            println!("no stack information available for address {addr:#x?}");
        }
        Err(e) => {
            println!("failed: {e}");
        }
    }
}

fn cmd_vars(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    for (_id, v) in db.static_variables() {
        if !args.is_empty() {
            if !v.name.contains(args) {
                continue;
            }
        }

        println!("0x{:0width$x} {}: {}", v.location, v.name, NamedGoff(db, v.type_id),
            width = db.pointer_size() as usize * 2);
    }
}

fn cmd_var(db: &debugdb::DebugDb, ctx: &mut Ctx, args: &str) {
    let results = db.static_variables_by_name(args).collect::<Vec<_>>();

    match results.len() {
        0 => println!("no variables found by that name"),
        1 => (),
        n => println!("note: {} variables found by that name", n),
    }

    for (_id, v) in results {
        println!("{} @ {}", v.name, Goff(v.offset));
        println!("- type: {}", NamedGoff(db, v.type_id));
        println!("- address: 0x{:x}", v.location);
        let Some(ty) = db.type_by_id(v.type_id) else { continue };

        match Value::from_state(&ctx.segments, v.location, db, &ty) {
            Ok(v) => {
                println!("- current contents: {}",
                    ValueWithDb(v, db));
            }
            Err(e) => {
                println!("- unable to display: {e}");
            }
        }
    }
}

fn cmd_addr(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    let addr = if args.starts_with("0x") {
        if let Ok(a) = u64::from_str_radix(&args[2..], 16) {
            a
        } else {
            println!("can't parse {} as an address", args);
            return;
        }
    } else if let Ok(a) = args.parse::<u64>() {
        a
    } else {
        println!("can't parse {} as an address", args);
        return;
    };

    let es = db.entities_by_address(addr).collect::<Vec<_>>();

    match es.len() {
        0 => println!("Nothing known about address 0x{:x}.", addr),
        1 => (),
        n => println!("note: {} overlapping entities claim address 0x{:x}", n, addr),
    }

    let bold = ansi_term::Style::new().bold();
    let dim = ansi_term::Style::new().dimmed();

    for e in es {
        let offset = addr - e.range.start;
        print!("Offset +0x{:x} into ", offset);
        match e.entity {
            debugdb::EntityId::Var(vid) => {
                let v = db.static_variable_by_id(vid).unwrap();
                println!("static {}", bold.paint(&v.name));
                println!("- range 0x{:x}..0x{:x}", 
                    e.range.start, e.range.end);
                println!("- type {}", NamedGoff(db, v.type_id));

                // Try to determine path within type.
                offset_to_path(db, v.type_id, offset);
            }
            debugdb::EntityId::Prog(pid) => {
                let p = db.subprogram_by_id(pid).unwrap();
                if let Some(n) = &p.name {
                    println!("subprogram {}", bold.paint(n));
                } else {
                    println!("subprogram {}", bold.paint("ANON"));
                }
                println!("- range 0x{:x}..0x{:x}", 
                    e.range.start, e.range.end);
                match db.static_stack_for_pc(addr) {
                    Ok(Some(trc)) => {
                        println!("- stack fragment with inlines:");
                        for (i, record) in trc.iter().rev().enumerate() {
                            let subp = db.subprogram_by_id(record.subprogram).unwrap();

                            print!("    {:4}   ", i);
                            if let Some(n) = &subp.name {
                                println!("{}", bold.paint(n));
                            } else {
                                println!("{}", bold.paint("<unknown-subprogram>"));
                            }
                            print!("{}", dim.prefix());
                            print!("        {}:", record.file);
                            if let Some(line) = record.line {
                                print!("{}:", line);
                            } else {
                                print!("?:");
                            }
                            if let Some(col) = record.column {
                                print!("{}", col);
                            } else {
                                print!("?");
                            }
                            print!("{}", dim.suffix());
                            println!();
                        }
                    }
                    Ok(None) => {
                        println!("- no stack fragment is available");
                    }
                    Err(e) => {
                        println!("- could not get stack fragment: {}", e);
                    }
                }
            }
        }
    }
}

fn offset_to_path(
    db: &debugdb::DebugDb,
    tid: TypeId,
    offset: u64,
) {
    let t = db.type_by_id(tid).unwrap();
    match t {
        Type::Array(a) => {
            let et = db.type_by_id(a.element_type_id).unwrap();
            if let Some(esz) = et.byte_size(db) {
                if esz > 0 {
                    let index = offset / esz;
                    let new_offset = offset % esz;
                    println!("  - index [{}] +0x{:x}", index, new_offset);
                    offset_to_path(db, a.element_type_id, new_offset);
                }
            }
        }
        Type::Struct(s) => {
            // This is where an offsetof-to-member index would be convenient

            for m in &s.members {
                if offset < m.location {
                    continue;
                }
                let new_offset = offset - m.location;
                let mt = db.type_by_id(m.type_id).unwrap();
                if let Some(msz) = mt.byte_size(db) {
                    if msz > 0 {
                        if let Some(n) = &m.name {
                            println!("  - .{} +0x{:x} (in {})", n, new_offset, s.name);
                        } else {
                            return;
                        }
                        offset_to_path(db, m.type_id, new_offset);
                        break;
                    }
                }
            }
        }
        _ => (),
    }
}

fn cmd_unwind(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    let addr = if args.starts_with("0x") {
        if let Ok(a) = u64::from_str_radix(&args[2..], 16) {
            a
        } else {
            println!("can't parse {} as an address", args);
            return;
        }
    } else if let Ok(a) = args.parse::<u64>() {
        a
    } else {
        println!("can't parse {} as an address", args);
        return;
    };

    use gimli::UnwindSection;
    let mut ctx = gimli::UnwindContext::new();
    let bases = gimli::BaseAddresses::default();
    match db.debug_frame.unwind_info_for_address(&bases, &mut ctx, addr, gimli::DebugFrame::cie_from_offset) {
        Ok(ui) => {
            println!("saved args: {} bytes", ui.saved_args_size());
            print!("cfa: ");
            match ui.cfa() {
                gimli::CfaRule::RegisterAndOffset { register, offset } => {
                    println!("reg #{}, offset {}", register.0, offset);
                }
                other => panic!("unsupported CFA rule type: {:?}", other),
            }
            for (n, rule) in ui.registers() {
                print!("  caller reg #{} ", n.0);
                match rule {
                    gimli::RegisterRule::Offset(n) => {
                        if *n < 0 {
                            println!("at CFA-{}", -n);
                        } else {
                            println!("at CFA+{}", n);
                        }
                    }
                    gimli::RegisterRule::ValOffset(n) => {
                        if *n < 0 {
                            println!("= CFA-{}", -n);
                        } else {
                            println!("= CFA+{}", n);
                        }
                    }
                    gimli::RegisterRule::SameValue => {
                        println!("preserved");
                    }
                    gimli::RegisterRule::Register(n) => {
                        println!("in reg# {}", n.0);
                    }
                    _ => println!("{:?}", rule),
                }
            }
        }
        Err(e) => {
            println!("failed: {}", e);
        }
    }
}

fn struct_picture(db: &DebugDb, s: &Struct, width: usize) {
    struct_picture_inner(
        db,
        s.byte_size,
        s.members.iter().enumerate().map(|(i, m)| (i, m, true)),
        width,
    )
}

fn struct_picture_inner<'a, N: Eq + Clone + Display>(
    db: &DebugDb,
    byte_size: Option<u64>,
    members: impl IntoIterator<Item = (N, &'a Member, bool)>,
    width: usize,
) {
    let Some(size) = byte_size else {
        println!("type has no size");
        return;
    };

    if size == 0 {
        println!("(type is 0 bytes long)");
        return;
    }

    let mut member_spans: RangeMap<u64, N> = RangeMap::new();
    let mut member_labels = vec![];
    for (i, m, in_legend) in members {
        if in_legend {
            member_labels.push({
                let label = if db.type_by_id(m.type_id).unwrap().byte_size(db) == Some(0) {
                    "(ZST)".to_string()
                } else {
                    i.to_string()
                };

                let name = if let Some(name) = &m.name {
                    name.as_str()
                } else {
                    "_"
                };
                if label == name {
                    format!("{name}: {}", NamedGoff(db, m.type_id))
                } else {
                    format!("{label} = {name}: {}", NamedGoff(db, m.type_id))
                }
            });
        }
        let offset = m.location;
        let Some(size) = db.type_by_id(m.type_id).unwrap().byte_size(db) else {
            continue;
        };
        if size != 0 {
            member_spans.insert(offset..offset + size, i);
        }
    }

    byte_picture(size, width, |off| {
        member_spans.get(&off).map(|x| x.to_string())
    });
    if !member_labels.is_empty() {
        println!("     where:");
        for label in member_labels {
            println!("       {label}");
        }
    }
}

fn enum_picture(db: &DebugDb, s: &Enum, width: usize) {
    let Some(size) = s.byte_size else {
        println!("type has no size");
        return;
    };

    if size == 0 {
        println!("(type is 0 bytes long)");
        return;
    }

    println!();

    match &s.shape {
        VariantShape::Zero => {
            println!("this enum is empty and cannot be diagrammed.");
        }
        VariantShape::One(_v) => {
            println!("this enum has only one variant (TODO)");
        }
        VariantShape::Many { member, .. } => {
            let Some(dlen) = db.type_by_id(member.type_id).unwrap().byte_size(db) else {
                println!("discriminator type has no size?");
                return;
            };
            let drange = member.location .. member.location + dlen;
            println!("Discriminator position:");
            byte_picture(size, width, |off| {
                if drange.contains(&off) {
                    Some("DISC".to_string())
                } else {
                    Some("body".to_string())
                }
            });
            /*
            for (disc, var) in variants {
                let show_disc = if let Some(v) = disc {
                    print!("DISC == {v:#x} => body: ");
                    true
                } else {
                    print!("else => body: ");
                    false
                };
                println!("{}", NamedGoff(db, var.member.type_id));
                let vt = db.type_by_id(var.member.type_id).unwrap();
                match vt {
                    Type::Struct(s) => {
                        let mut all_members = vec![];
                        if show_disc {
                            all_members.push(("DISC", member, false));
                        }
                        all_members.extend(
                            s.members.iter().map(|(n, m)| {
                                let mut n = n.as_str();
                                if n.len() > 6 {
                                    n = &n[..6];
                                }

                                (n, m, true)
                            })
                        );
                        struct_picture_inner(db, s.byte_size, all_members, width);
                    },
                    _ => println!("(can't display non-struct)"),
                }
            }
            */
        }
    }
}

fn byte_picture(
    size: u64,
    width: usize,
    owner: impl Fn(u64) -> Option<String>,
) {
    let width = width as u64;
    print!("      ");
    for byte in 0..u64::min(size, width) {
        print!(" {byte:^6}");
    }
    println!();

    let wordcount = (size + (width - 1)) / width;
    let mut current = None;
    let mut above = vec![None; width as usize];
    for word in 0..wordcount {
        print!("     +");
        for byte in 0..width {
            let n = owner(word * width + byte);
            if above[byte as usize] == Some(n) {
                print!("      +");
            } else {
                print!("------+");
            }
        }
        println!();

        print!("{:04x} |", word * width);
        for byte in 0..width {
            let off = word * width + byte;
            let n = owner(off);
            if Some(&n) != current.as_ref() {
                if byte != 0 {
                    print!("|");
                }
                if let Some(i) = &n {
                    print!("{:^6}", i);
                } else {
                    if off < size {
                        print!(" pad  ");
                    } else {
                        print!("      ");
                    }
                }
                current = Some(n.clone());
            } else {
                if byte != 0 {
                    print!(" ");
                }
                print!("      ");
            }

            if byte == width - 1 {
                if off < size {
                    println!("|");
                } else {
                    println!();
                }
            }

            above[byte as usize] = Some(n);
        }
    }
    print!("     +");
    let final_bar = if size % width == 0 { width } else { size % width };
    for _ in 0..final_bar {
        print!("------+");
    }
    println!();
}

fn cmd_decode(db: &debugdb::DebugDb, ctx: &mut Ctx, args: &str) {
    let (addrstr, mut typestr) = if let Some(space) = args.find(' ') {
        args.split_at(space)
    } else {
        println!("usage: decode [addr] [typename blah blah]");
        return;
    };
    let addr = match parse_int::parse::<u64>(addrstr) {
        Ok(x) => x,
        Err(e) => {
            println!("bad address: {e}");
            return;
        }
    };

    let asmutref = Regex::new(r#"^ +as +[&*]mut (.*)$"#).unwrap();
    let asref = Regex::new(r#"^ +as +&(.*)$"#).unwrap();
    let asptr = Regex::new(r#"^ +as +\*(const|_) (.*)$"#).unwrap();

    if let Some(c) = asmutref.captures(typestr) {
        typestr = c.get(1).unwrap().as_str();
    } else if let Some(c) = asref.captures(typestr) {
        typestr = c.get(1).unwrap().as_str();
    } else if let Some(c) = asptr.captures(typestr) {
        typestr = c.get(2).unwrap().as_str();
    }

    let types: Vec<_> = match parse_type_name(typestr.trim()) {
        None => return,
        Some(ParsedTypeName::Name(n)) => {
            db.types_by_name(n).collect()
        }
        Some(ParsedTypeName::Goff(o)) => {
            db.type_by_id(o).into_iter()
                .map(|t| (o, t))
                .collect()
        }
    };

    let many = match types.len() {
        0 => {
            println!("{}", ansi_term::Colour::Red.paint("No types found."));
            return;
        }
        1 => false,
        n => {
            println!("{}{} types found with that name:",
                ansi_term::Color::Yellow.paint("note: "),
                n,
            );
            true
        }
    };

    for (goff, t) in types {
        if many { println!() }
        println!("{}: ", NamedGoff(db, goff));
        match Value::from_state(&ctx.segments, addr, db, t) {
            Ok(v) => {
                println!("{}", ValueWithDb(v, db));
            }
            Err(e) => {
                println!("could not parse as this type: {e}");
            }
        }
    }
}

fn cmd_decode_async(db: &debugdb::DebugDb, ctx: &mut Ctx, args: &str) {
    let (addrstr, typestr) = if let Some(space) = args.find(' ') {
        args.split_at(space)
    } else {
        println!("usage: decode-async [addr] [typename blah blah]");
        return;
    };
    let addr = match parse_int::parse::<u64>(addrstr) {
        Ok(x) => x,
        Err(e) => {
            println!("bad address: {e}");
            return;
        }
    };
    let types: Vec<_> = match parse_type_name(typestr.trim()) {
        None => return,
        Some(ParsedTypeName::Name(n)) => {
            db.types_by_name(n).collect()
        }
        Some(ParsedTypeName::Goff(o)) => {
            db.type_by_id(o).into_iter()
                .map(|t| (o, t))
                .collect()
        }
    };

    let many = match types.len() {
        0 => {
            println!("{}", ansi_term::Colour::Red.paint("No types found."));
            return;
        }
        1 => false,
        n => {
            println!("{}{} types found with that name:",
                ansi_term::Color::Yellow.paint("note: "),
                n,
            );
            true
        }
    };

    for (goff, t) in types {
        if many { println!() }
        println!("{}: ", NamedGoff(db, goff));
        let mut v = &match Value::from_state(&ctx.segments, addr, db, t) {
            Ok(v) => v,
            Err(e) => {
                println!("could not parse as this type: {e}");
                return;
            }
        };
        let parts = Regex::new(r#"^(.*)::\{async_(fn|block)_env#0\}(<.*)?$"#).unwrap();
        let suspend_state = Regex::new(r#"::Suspend([0-9]+)$"#).unwrap();
        let mut first = true;
        let bold = ansi_term::Style::new().bold();
        loop {
            if !first {
                print!("waiting on: ");
            }
            first = false;
            let Value::Enum(e) = v else {
                println!("{}hand-rolled future{}", bold.prefix(), bold.suffix());
                println!("    type: {}", v.type_name());
                break;
            };
            let Some(parts) = parts.captures(&e.name) else {
                println!("(name is weird for an async fn env)");
                break;
            };
            let name = &parts[1];
            let parms = parts.get(3).map(|m| m.as_str()).unwrap_or("");
            println!("async fn {}{name}{parms}{}", bold.prefix(), bold.suffix());
            let state = &e.disc;
            let state_name = &e.value.name;

            if state_name.ends_with("Unresumed") {
                println!("    future has not yet been polled");
                break;
            } else if state_name.ends_with("Returned") {
                println!("    future has already resolved");
                break;
            } else if state_name.ends_with("Panicked") {
                println!("    future panicked on previous poll");
                break;
            } else if let Some(sc) = suspend_state.captures(state_name) {
                if let Ok(n) = sc[1].parse::<usize>() {
                    println!("    suspended at await point {n}");
                } else {
                    println!("    unrecognized state {state}: {state_name}");
                }
            } else {
                println!("    unrecognized state {state}: {state_name}");
            }

            let mut awaitees = e.value.members_named("__awaitee");
            let Some(awaitee) = awaitees.next() else {
                println!(" (stopped unexpectedly)");
                break;
            };
            if awaitees.next().is_some() {
                println!(" (multiple __awaitee fields)");
                break;
            }
            v = awaitee;
        }
    }
}

fn cmd_decode_blob(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    let type_name = args.trim();
    let types: Vec<_> = match parse_type_name(type_name) {
        None => return,
        Some(ParsedTypeName::Name(n)) => {
            db.types_by_name(n).collect()
        }
        Some(ParsedTypeName::Goff(o)) => {
            db.type_by_id(o).into_iter()
                .map(|t| (o, t))
                .collect()
        }
    };

    let many = match types.len() {
        0 => {
            println!("{}", ansi_term::Colour::Red.paint("No types found."));
            return;
        }
        1 => false,
        n => {
            println!("{}{} types found with that name:",
                ansi_term::Color::Yellow.paint("note: "),
                n,
            );
            true
        }
    };

    println!("Paste hex-encoded memory blob. Whitespace OK.");
    println!("Address prefix ending in colon will be removed.");
    println!("Enter a blank line to end.");

    let stdin = std::io::stdin().lock();
    let mut img = vec![];
    for line in stdin.lines() {
        let line = match line {
            Err(e) => {
                println!("input error: {e}");
                return;
            }
            Ok(v) => v,
        };
        let mut line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            line = &line.split_at(colon).1[1..];
        }

        let mut hexits = vec![];
        for b in line.bytes() {
            match b {
                b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                    hexits.push(b);
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                _ => {
                    println!("unexpected byte in input: {b:#x?}");
                    return;
                }
            }
        }

        let bytes = hexits.chunks_exact(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16))
            .collect::<Result<Vec<_>, _>>();
        match bytes {
            Err(e) => {
                println!("couldn't parse that: {e}");
                return;
            }
            Ok(b) => img.extend(b),
        }
    }

    for (goff, t) in types {
        if many { println!() }
        println!("{}: ", NamedGoff(db, goff));
        let Some(size) = t.byte_size(db) else {
            println!("  (type is unsized, cannot decode)");
            continue;
        };
        let Ok(size) = usize::try_from(size) else {
            println!("  (type too big for this platform)");
            continue;
        };
        let mut this_img = img.clone();
        if size > this_img.len() {
            println!("(padding entered data to {size} bytes)");
            this_img.resize(size, 0);
        }
        let machine = ImgMachine::new(this_img);
        match Value::from_state(&machine, 0, db, t) {
            Ok(v) => {
                println!("{}", ValueWithDb(v, db));
            }
            Err(e) => {
                println!("could not parse as this type: {e}");
            }
        }
    }
}

fn cmd_decode_async_blob(db: &debugdb::DebugDb, _ctx: &mut Ctx, args: &str) {
    let type_name = args.trim();
    let types: Vec<_> = match parse_type_name(type_name) {
        None => return,
        Some(ParsedTypeName::Name(n)) => {
            db.types_by_name(n).collect()
        }
        Some(ParsedTypeName::Goff(o)) => {
            db.type_by_id(o).into_iter()
                .map(|t| (o, t))
                .collect()
        }
    };

    let many = match types.len() {
        0 => {
            println!("{}", ansi_term::Colour::Red.paint("No types found."));
            return;
        }
        1 => false,
        n => {
            println!("{}{} types found with that name:",
                ansi_term::Color::Yellow.paint("note: "),
                n,
            );
            true
        }
    };

    println!("Paste hex-encoded memory blob. Whitespace OK.");
    println!("Address prefix ending in colon will be removed.");
    println!("Enter a blank line to end.");

    let stdin = std::io::stdin().lock();
    let mut img = vec![];
    for line in stdin.lines() {
        let line = match line {
            Err(e) => {
                println!("input error: {e}");
                return;
            }
            Ok(v) => v,
        };
        let mut line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            line = &line.split_at(colon).1[1..];
        }

        let mut hexits = vec![];
        for b in line.bytes() {
            match b {
                b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                    hexits.push(b);
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                _ => {
                    println!("unexpected byte in input: {b:#x?}");
                    return;
                }
            }
        }

        let bytes = hexits.chunks_exact(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16))
            .collect::<Result<Vec<_>, _>>();
        match bytes {
            Err(e) => {
                println!("couldn't parse that: {e}");
                return;
            }
            Ok(b) => img.extend(b),
        }
    }

    for (goff, t) in types {
        if many { println!() }
        println!("{}: ", NamedGoff(db, goff));
        let Some(size) = t.byte_size(db) else {
            println!("  (type is unsized, cannot decode)");
            continue;
        };
        let Ok(size) = usize::try_from(size) else {
            println!("  (type too big for this platform)");
            continue;
        };
        let mut this_img = img.clone();
        if size > this_img.len() {
            println!("(padding entered data to {size} bytes)");
            this_img.resize(size, 0);
        }
        let machine = ImgMachine::new(this_img);
        let mut v = &match Value::from_state(&machine, 0, db, t) {
            Ok(v) => v,
            Err(e) => {
                println!("could not parse as this type: {e}");
                return;
            }
        };
        let parts = Regex::new(r#"^(.*)::\{async_(fn|block)_env#0\}(<.*)?$"#).unwrap();
        let suspend_state = Regex::new(r#"::Suspend([0-9]+)$"#).unwrap();
        let mut first = true;
        loop {
            if !first {
                print!("waiting on: ");
            }
            first = false;
            let Value::Enum(e) = v else {
                println!("hand-rolled future");
                println!("    type: {}", v.type_name());
                break;
            };
            let Some(parts) = parts.captures(&e.name) else {
                println!("(name is weird for an async fn env)");
                break;
            };
            let name = &parts[1];
            let parms = parts.get(3).map(|m| m.as_str()).unwrap_or("");
            println!("async fn {name}{parms}");
            let state = &e.disc;
            let state_name = &e.value.name;

            if state_name.ends_with("Unresumed") {
                println!("    future has not yet been polled");
                break;
            } else if state_name.ends_with("Returned") {
                println!("    future has already resolved");
                break;
            } else if state_name.ends_with("Panicked") {
                println!("    future panicked on previous poll");
                break;
            } else if let Some(sc) = suspend_state.captures(state_name) {
                if let Ok(n) = sc[1].parse::<usize>() {
                    println!("    suspended at await point {n}");
                } else {
                    println!("    unrecognized state {state}: {state_name}");
                }
            } else {
                println!("    unrecognized state {state}: {state_name}");
            }

            let mut awaitees = e.value.members_named("__awaitee");
            let Some(awaitee) = awaitees.next() else {
                println!(" (stopped unexpectedly)");
                break;
            };
            if awaitees.next().is_some() {
                println!(" (multiple __awaitee fields)");
                break;
            }
            v = awaitee;
        }
    }
}


fn cmd_load(
    _db: &debugdb::DebugDb,
    ctx: &mut Ctx,
    args: &str,
) {
    let args = args.trim();
    let words = args.split_whitespace().collect::<Vec<_>>();
    if words.len() != 2 {
        println!("usage: load [filename] [address]");
        return;
    }
    let filename = words[0];
    let address = match parse_int::parse::<u64>(words[1]) {
        Ok(a) => a,
        Err(e) => {
            println!("bad address: {e}");
            return;
        }
    };

    let image = match std::fs::read(filename) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("unable to read file: {e}");
            return;
        }
    };

    let end = address + u64::try_from(image.len()).unwrap();

    ctx.segments.insert(address..=end, image);
}

fn cmd_stack(db: &debugdb::DebugDb, ctx: &mut Ctx, _args: &str) {
    let (stack_ty, dead_val, wid) = match db.pointer_size() {
        4 => ("u32", 0xDEDEDEDE, 10),
        8 => ("u64", 0xDEDEDEDE_DEDEDEDE, 18),
        _ => {
            println!("unsupported image pointer size");
            return;
        }
    };
    match get_stack_used(&ctx.segments, db, stack_ty, dead_val) {
        Ok(Some((base, used, top))) => {
            let bytes_used = top - used;
            let bytes_avail = top - base;
            let free = used - base;
            println!("stack top:         {top:#wid$x}");
            println!("lowest stack used: {used:#wid$x}");
            println!("bytes used: {bytes_used} / {bytes_avail} ({free} free)");
        }
        Ok(None) => {
            println!("can't determine stack shape");
        }
        Err(e) => {
            println!("can't access stack: {e}");
        }
    }
}

fn cmd_time(db: &debugdb::DebugDb, ctx: &mut Ctx, _args: &str) {
    if let Some(tv) = find_time_vars(db) {
        match get_time(&ctx.segments, db, &tv) {
            Ok(t) => {
                println!("current tick-time is: {t}");
            },
            Err(e) => {
                println!("error loading time: {e}");
            }
        }
    } else {
        println!("could not find time vars");
    }
}

fn cmd_tasks(db: &debugdb::DebugDb, ctx: &mut Ctx, args: &str) {
    let mut verbose = false;
    for word in args.split_whitespace() {
        match word {
            "-v" => verbose = true,
            _ => {
                println!("usage: tasks {{-v}}");
                return;
            }
        }
    }

    let time = {
        if let Some(tv) = find_time_vars(db) {
            match get_time(&ctx.segments, db, &tv) {
                Ok(t) => {
                    println!("current tick-time is: {t}");
                    Some(t)
                },
                Err(e) => {
                    println!("error loading time: {e}");
                    None
                }
            }
        } else {
            println!("could not find time vars");
            None
        }
    };

    let Some((_, futures)) = db.unique_static_variable_by_name("lilos::exec::TASK_FUTURES") else {
        println!("{}", ansi_term::Colour::Red.paint("missing lilos::exec::TASK_FUTURES var"));
        return;
    };

    let Some(ty) = db.type_by_id(futures.type_id) else {
        println!("{}", ansi_term::Colour::Red.paint("lilos::exec::TASK_FUTURES var has invalid type"));
        return;
    };

    let val = match Value::from_state(&ctx.segments, futures.location, db, &ty) {
        Ok(v) => v,
        Err(e) => {
            println!("{}{e}", ansi_term::Colour::Red.paint("can't load lilos::exec::TASK_FUTURES: "));
            return;
        }
    };
    let Value::Enum(val) = val else {
        println!("{}", ansi_term::Colour::Red.paint("lilos::exec::TASK_FUTURES type has wrong shape"));
        return;
    };
    if val.disc != "Some" {
        println!("{}", ansi_term::Colour::Red.paint("lilos::exec::TASK_FUTURES not set - has scheduler started?"));
        return;
    }

    let Some(Value::Struct(slice)) = val.value.members_named("__0").next() else {
        println!("{}", ansi_term::Colour::Red.paint("lilos::exec::TASK_FUTURES type has wrong shape"));
        return;
    };
    let Some(Value::Pointer(data_ptr)) = slice.members_named("data_ptr").next() else {
        println!("{}", ansi_term::Colour::Red.paint("lilos::exec::TASK_FUTURES type has wrong shape"));
        return;
    };
    let Some(Value::Base(length)) = slice.members_named("length").next() else {
        println!("{}", ansi_term::Colour::Red.paint("lilos::exec::TASK_FUTURES type has wrong shape"));
        return;
    };
    let length = length.as_u64().unwrap();
    let Some(pointee) = db.type_by_id(data_ptr.dest_type_id) else {
        println!("{}", ansi_term::Colour::Red.paint("pointee type missing ???"));
        return;
    };
    let Some(pointee_size) = pointee.byte_size(db) else {
        println!("{}", ansi_term::Colour::Red.paint("pointee unsized ???"));
        return;
    };
    let dynptr = Regex::new(r#"^[&*](mut )?dyn (.*)$"#).unwrap();
    for i in 0..length {
        println!("{}task {i}:{}", Colour::Green.prefix(), Colour::Green.suffix());
        let addr = data_ptr.value + i * pointee_size;
        let elt = match value::Struct::from_state(&ctx.segments, addr, db, pointee) {
            Ok(e) => e,
            Err(e) => {
                println!("{} failed to load task pointer {i}: {e}", ansi_term::Colour::Red.paint("error:"));
                return;
            }
        };
        let Some(Value::Struct(fat_pointer)) = elt.any_member_named("pointer") else {
            println!("Pin missing pointer member");
            return;
        };
        let Some(_dyn_caps) = dynptr.captures(&fat_pointer.name) else {
            println!("dyn pointer name format unexpected: {}",
                &fat_pointer.name);
            return;
        };
        let Some(data_pointer) = fat_pointer.any_member_named("pointer") else {
            println!("bad fat pointer");
            return;
        };
        let Some(vtable) = fat_pointer.any_member_named("vtable") else {
            println!("bad fat pointer");
            return;
        };

        let Some(data_addr) = data_pointer.pointer_value() else {
            println!("data_ptr not a pointer?");
            return;
        };
        let Some(vt_addr) = vtable.pointer_value() else {
            println!("vtable not a pointer?");
            return;
        };

        let mut concrete_type = None;
        'searchloop:
        for e in db.entities_by_address(vt_addr) {
            if vt_addr != e.range.start {
                continue;
            }
            let EntityId::Var(v) = e.entity else { continue };
            let Some(v) = db.static_variable_by_id(v) else { continue };

            let vtable = Regex::new(r#"^<(.*) as (.*)>::\{vtable\}$"#).unwrap();
            let Some(vc) = vtable.captures(&v.name) else { continue };
            let concrete = &vc[1];

            for (tid, ty) in db.types_by_name(concrete) {
                if matches!(ty, Type::Enum(_)) {
                    // Good enough.
                    concrete_type = Some((tid, ty));
                    break 'searchloop;
                }
            }
        }

        let Some((_concrete_tid, concrete_ty)) = concrete_type else {
            println!("concrete type for vtable not found: {vt_addr:#x}");
            return;
        };

        let outer = match Value::from_state(&ctx.segments, data_addr, db, concrete_ty) {
            Ok(v) => v,
            Err(e) => {
                println!("could not parse as this type: {e}");
                return;
            }
        };
        let mut v = &outer;
        let mut first = true;
        let bold = ansi_term::Style::new().bold();
        loop {
            if !first {
                print!("waiting on: ");
            }
            first = false;

            let next = await_trace_frame(
                ctx,
                db,
                time,
                v,
            );
            if let Some(n) = next {
                v = n;
            } else {
                break;
            }
        }
        if verbose {
            println!("{}", bold.paint("full dump:"));
            println!("{}", ValueWithDb(outer, db));
        }
    }
}

fn await_trace_frame<'v>(
    ctx: &Ctx,
    db: &DebugDb,
    time: Option<u64>,
    value: &'v Value,
) -> Option<&'v Value> {
    let parts = Regex::new(r#"^(.*)::\{async_(fn|block)_env#0\}(<.*)?$"#).unwrap();
    let suspend_state = Regex::new(r#"::Suspend([0-9]+)$"#).unwrap();
    let bold = ansi_term::Style::new().bold();

    let Value::Enum(e) = value else {
        return await_trace_handroll(ctx, db, time, value);
    };
    let Some(parts) = parts.captures(&e.name) else {
        println!("(name is weird for an async fn env)");
        return None;
    };
    let name = &parts[1];
    let parms = parts.get(3).map(|m| m.as_str()).unwrap_or("");
    println!("async fn {}{name}{parms}{}", bold.prefix(), bold.suffix());
    let state = &e.disc;
    let state_name = &e.value.name;

    let state = if state_name.ends_with("Unresumed") {
        AsyncFnState::Unresumed
    } else if state_name.ends_with("Returned") {
        AsyncFnState::Returned
    } else if state_name.ends_with("Panicked") {
        AsyncFnState::Panicked
    } else if let Some(sc) = suspend_state.captures(state_name) {
        if let Ok(n) = sc[1].parse::<usize>() {
            AsyncFnState::Suspend(n)
        } else {
            println!("    unrecognized state {state}: {state_name}");
            return None;
        }
    } else {
        println!("    unrecognized state {state}: {state_name}");
        return None;
    };

    // Try and report the line number (decl coords). The decl coords are present
    // on the enum variant member. That is,
    //
    // enum yadda::yadda::{async_fn_env#0}
    //      variant 2
    //          member
    //              decl coords here
    //
    // So, we need to find the actual type (rather than the reflected enum,
    // which we've been using as a shortcut), and then find the variant. The
    // variant names don't match the state struct names (e.g. they are not
    // things like Suspend0), so we have to do the matching by _also_ getting
    // the tid of the state struct, and checking if the member matches that
    // type.
    //
    // Whee.
    //
    // First we'll see if we can find a tid for the state struct.
    let mut has_decl_coords = false;
    if let Some((state_tid, _)) = db.types_by_name(state_name).next() {
        // Cool. See if we can find the enum type. There can easily be more than
        // one such type; we'll process the first one that seems vaguely
        // plausible.
        'enumloop:
        for (_tid, ty) in db.types_by_name(&e.name) {
            // We expect the type to be an enum.
            let Type::Enum(ty) = ty else { continue };
            // We expect the enum to have at least four variants, because
            // that's how async fn enums currently work, which means we only
            // have to handle one
            // of the possible variantshapes.
            let VariantShape::Many { variants, .. } = &ty.shape
                else { continue };
            // We expect one of the variants' members to correspond to the state
            // struct tid.
            for v in variants.values() {
                if v.member.type_id == state_tid {
                    // Wow! We found it!
                    //
                    // ... does it have decl coord information?
                    if v.member.decl_coord.is_useful() {
                        let d = &v.member.decl_coord; // shorthand
                        print!("    suspended at {}:", d.file.as_deref().unwrap_or("???"));
                        if let Some(n) = d.line {
                            print!("{n}");
                        } else {
                            print!("???");
                        }
                        // Be more tolerant of missing columns; they're often
                        // missing.
                        if let Some(n) = d.column {
                            print!(":{n}");
                        }
                        println!();
                        has_decl_coords = true;
                        // Stop processing things
                        break 'enumloop;
                    }
                }
            }
        }
    }


    match name {
        "lilos::exec::sleep_until" => {
            match get_async_fn_local(value, "deadline") {
                Ok(Some(deadline)) => {
                    if let Some(t) = deadline.newtype("lilos::time::TickTime") {
                        if let Some(t) = t.u64_value() {
                            print!("    sleeping until: {}", t);
                            if let Some(time) = time {
                                if time < t {
                                    let n = t - time;
                                    print!(" ({n} ms from now)");
                                } else if time == t {
                                    print!(" (now)");
                                } else {
                                    let n = time - t;
                                    print!(" {}({n} ms ago!){}",
                                    Colour::Red.prefix(),
                                    Colour::Red.suffix());
                                }
                            }
                            println!();
                        }
                    }
                    return None;
                }
                Ok(None) => println!("no local"),
                Err(e) => println!("{e:?}"),
            }
        }
        "lilos::spsc::{impl#4}::pop" => {
            match get_async_fn_local(value, "self") {
                Ok(Some(shelf)) => {
                    if let Value::Pointer(p) = shelf {
                        match get_spsc_from_handle(
                            &ctx.segments,
                            db,
                            p.value,
                            p.dest_type_id,
                        ) {
                            Ok((qty, addr)) => {
                                println!("    waiting for data in spsc queue at {addr:#x}");
                                println!("    queue type: {}", NamedGoff(db, qty));
                            }
                            Err(e) => {
                                println!("    can't interpret: {e}");
                            }
                        }
                        return None;
                    }
                }
                Ok(None) => println!("no local"),
                Err(e) => println!("{e:?}"),
            }
        }
        _ => (),
    }

    match state {
        AsyncFnState::Unresumed =>  {
            println!("    future has not yet been polled");
            return None;
        }
        AsyncFnState::Returned => {
            println!("    future has already resolved");
            return None;
        }
        AsyncFnState::Panicked => {
            println!("    future panicked on previous poll");
            return None;
        }
        AsyncFnState::Suspend(n) => {
            if !has_decl_coords {
                println!("    suspended at await point {n}");
            }
        }
    }

    let mut awaitees = e.value.members_named("__awaitee");
    let Some(awaitee) = awaitees.next() else {
        println!(" (stopped unexpectedly)");
        return None;
    };
    if awaitees.next().is_some() {
        println!(" (multiple __awaitee fields)");
        return None;
    }
    Some(awaitee)
}

fn await_trace_handroll<'v>(
    _ctx: &Ctx,
    db: &DebugDb,
    _time: Option<u64>,
    value: &'v Value,
) -> Option<&'v Value> {
    let bold = ansi_term::Style::new().bold();

    match value {
        Value::Struct(s) => {
            if s.name.starts_with("lilos::exec::Until<") {
                if let Some(notify) = s.unique_member_named("notify") {
                    if let Value::Pointer(p) = notify {
                        print!("{}notify ",
                            bold.prefix());

                        let mut named = false;
                        for ar in db.entities_by_address(p.value) {
                            if ar.range.start == p.value {
                                if let EntityId::Var(v) = ar.entity {
                                    let v = db.static_variable_by_id(v).unwrap();
                                    print!("{}", v.name);
                                    named = true;
                                    break;
                                }
                            }
                        }

                        if !named {
                            print!("at {:#x}", p.value);
                        }
                        println!("{}", bold.suffix());

                        if let Some(cond) = s.unique_member_named("cond") {
                            println!("    predicate: {}", cond.type_name());
                        }
                        return None;
                    }
                }
            }
        }
        _ => (),
    }

    println!("{}hand-rolled future{}", bold.prefix(), bold.suffix());
    println!("    type: {}", value.type_name());
    None
}

enum AsyncFnState {
    Unresumed,
    Returned,
    Panicked,
    Suspend(usize),
}

fn get_async_fn_local<'e>(env: &'e Value, name: &str) -> Result<Option<&'e Value>, LocalError> {
    let Value::Enum(env) = env else { return Err(LocalError::NotEnum) };
    let parts = Regex::new(r#"^(.*)::\{async_fn_env#0\}(<.*)?$"#).unwrap();
    let Some(_parts) = parts.captures(&env.name) else {
        return Err(LocalError::NotAnEnv);
    };

    let mut members = env.value.members_named(name);
    let Some(m) = members.next() else { return Ok(None) };
    //if members.next().is_some() { return Err(LocalError::Ambiguous); }

    Ok(Some(m))
}

#[derive(Copy, Clone, Debug)]
enum LocalError {
    NotEnum,
    NotAnEnv,
}

fn find_time_vars(db: &DebugDb) -> Option<TimeVars> {
    let (tick, _) = db.unique_static_variable_by_name("lilos::time::TICK")?;
    let epoch = db.unique_static_variable_by_name("lilos::time::EPOCH")
        .map(|(id, _info)| id);
    Some(TimeVars { tick, epoch })
}

struct TimeVars {
    tick: VarId,
    epoch: Option<VarId>,
}

fn get_time<M: Machine>(machine: &M, db: &DebugDb, time_vars: &TimeVars) -> Result<u64, LoadError<M::Error>> {
    let low = {
        let tick = db.static_variable_by_id(time_vars.tick).unwrap();
        let tick_type = db.type_by_id(tick.type_id).unwrap();
        let low = core::sync::atomic::AtomicU32::from_state(machine, tick.location, db, tick_type)?;
        low.load(Ordering::Relaxed)
    };

    let high = if let Some(epoch) = time_vars.epoch {
        let ep = db.static_variable_by_id(epoch).unwrap();
        let ep_type = db.type_by_id(ep.type_id).unwrap();
        let high = core::sync::atomic::AtomicU32::from_state(machine, ep.location, db, ep_type)?;
        high.load(Ordering::Relaxed)
    } else {
        0
    };

    Ok(u64::from(low) | u64::from(high) << 32)
}

fn get_spsc_from_handle<M: Machine>(machine: &M, db: &DebugDb, address: u64, handle_tid: TypeId) -> Result<(TypeId, u64), LoadError<M::Error>> {

    let handle_ty = db.type_by_id(handle_tid).unwrap();
    let Type::Struct(handle_ty) = handle_ty else {
        return Err(LoadError::NotAStruct);
    };
    let Some(q_m) = handle_ty.unique_member("q") else {
        return Err(LoadError::MissingMember("q".to_string()));
    };
    let q_ty = db.type_by_id(q_m.type_id).unwrap();
    let p = value::Pointer::from_state(machine, address + q_m.location, db, q_ty)?;
    Ok((p.dest_type_id, p.value))
}

fn get_stack_used<M: Machine>(machine: &M, db: &DebugDb, unit: &str, value: u64) -> Result<Option<(u64, u64, u64)>, LoadError<M::Error>> {
    let stack_start = db.unique_raw_symbol_by_name("_stack_start").unwrap();

    let stack_limit = db.unique_raw_symbol_by_name("_stack_limit");

    let stack_base = if let Some(limit) = stack_limit {
        // Trust an explicit symbol over any heuristic.
        limit
    } else {
        let heap_start = db.unique_raw_symbol_by_name("__sheap").unwrap();

        if stack_start > heap_start {
            // Assume conventional memory layout (open to stack clash)
            heap_start
        } else {
            println!("cannot determine maximum extent of stack.");
            println!("stack does not grow toward heap, and no _stack_limit symbol is present.");
            return Ok(None);
        }
    };

    let (_, unit_ty) = db.types_by_name(unit).next().unwrap();
    let unit = unit_ty.byte_size(db).unwrap();
    let unit = usize::try_from(unit).unwrap();
    
    for addr in (stack_base..stack_start).step_by(unit) {
        let chunk = value::Base::from_state(machine, addr, db, unit_ty)?;
        if chunk.as_u64().unwrap() != value {
            // We've found the first written word of the stack!
            return Ok(Some((stack_base, addr, stack_start)));
        }
    }
    // If we fall out of the loop, it's because the entire stack has intact
    // scribbles.
    Ok(Some((stack_base, stack_start, stack_start)))
}

fn cmd_reg(_db: &debugdb::DebugDb, ctx: &mut Ctx, args: &str) {
    let mut words = args.split_whitespace();
    let Some(regnum_str) = words.next() else {
        println!("missing required register number argument");
        return;
    };
    let value_str = words.next();

    let Ok(regnum) = parse_int::parse::<u16>(regnum_str) else {
        println!("could not parse register: {regnum_str}");
        return;
    };

    if let Some(value_str) = value_str {
        let Ok(value) = parse_int::parse::<u64>(value_str) else {
            println!("could not parse value: {value_str}");
            return;
        };
        ctx.registers.insert(regnum, value);
    } else {
        if let Some(x) = ctx.register(regnum) {
            println!("register {regnum} = {x:#x}");
        } else {
            println!("register {regnum} not present in machine state");
        }
    }
}
