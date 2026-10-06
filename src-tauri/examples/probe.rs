fn main() {
    let args: Vec<String> = std::env::args().collect();
    let what = args.get(1).map(String::as_str).unwrap_or("system");
    let arg = args.get(2).map(String::as_str).unwrap_or("");
    println!("{}", nexfix_lib::probe_json(what, arg));
}
