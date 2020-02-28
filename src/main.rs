use clap::{App, Arg, SubCommand};
use rpassword::read_password;

mod ecc;
mod entropy;
mod mnemonic;

fn main() {
    let args = App::new("Bitcoin command-line tool")
        .author("Zhang Yu <archerfeel@gmail.com>")
        .subcommand(SubCommand::with_name("verify"))
        .subcommand(
            SubCommand::with_name("gen")
                .help("generate a private key with n(12,15,18,18,21,24) mnemonic phrase")
                .arg(
                    Arg::with_name("number")
                        .help("the NUMBER of mnemonic phrase")
                        .short("i")
                        .value_name("NUMBER")
                        .default_value("12"),
                )
                .arg(
                    Arg::with_name("emptypass")
                        .short("n")
                        .long("no-pass")
                        .help("no pass phrase")
                        .takes_value(false),
                ),
        )
        .subcommand(
            SubCommand::with_name("inspect")
                .help("inspect private key using given mnemonic phrase")
                .arg(Arg::with_name("phrase").multiple(true).takes_value(true))
                .arg(
                    Arg::with_name("emptypass")
                        .short("n")
                        .long("no-pass")
                        .help("no pass phrase")
                        .takes_value(false),
                ),
        )
        .get_matches();
    match args.subcommand() {
        ("gen", Some(gen)) => {
            let number: usize = gen.value_of("number").unwrap().parse::<usize>().unwrap();
            if number != 12 && number != 15 && number != 18 && number != 21 && number != 24 {
                eprintln!("NUMBER must be 12,15,18,21,24");
                std::process::exit(1);
            }
            let mut bytes = number * 11 / 8;
            bytes = if bytes == 33 { 32 } else { bytes };
            let entropy = entropy::Entropy::gen(bytes);
            let memo = entropy.to_mnemonic();
            let phrase = memo.to_phrase();
            let passphrase = if gen.is_present("emptypass") {
                "".to_string()
            } else {
                println!("Type a password:");
                let passphrase = read_password().unwrap();
                println!("Confirm password:");
                let confirm = read_password().unwrap();
                if passphrase != confirm {
                    eprintln!("Password mismatch");
                    std::process::exit(1);
                }
                confirm
            };
            let seed = mnemonic::inspect_seed(&phrase, &passphrase);
            let (sk, pk, addr) = ecc::new_key(&seed[0..32]);
            println!("{}", phrase);
            println!("Private key: {:x}", sk);
            println!("Public key: {:x}", pk);
            println!("Wallet Address: {}", addr);
        }
        ("inspect", Some(inspect)) => {
            let phrase = inspect
                .values_of("phrase")
                .unwrap()
                .collect::<Vec<&str>>()
                .join(" ")
                .trim()
                .to_string();
            let memo = mnemonic::Mnemonic::from_phrase(&phrase);
            if memo.is_err() {
                eprintln!("phrase error: {}", memo.err().unwrap());
                std::process::exit(1);
            }
            let entropy = entropy::Entropy::from_mnemonic(&memo.expect(""));
            if entropy.is_err() {
                eprintln!("entropy error: {}", entropy.err().unwrap());
                std::process::exit(1);
            }
            let passphrase = if inspect.is_present("emptypass") {
                "".to_string()
            } else {
                println!("Type a password:");
                let passphrase = read_password().unwrap();
                println!("Confirm password:");
                let confirm = read_password().unwrap();
                if passphrase != confirm {
                    eprintln!("Password mismatch");
                    std::process::exit(1);
                }
                confirm
            };
            let seed = mnemonic::inspect_seed(&phrase, &passphrase);
            let (sk, pk, addr) = ecc::new_key(&seed[0..32]);
            println!("Private key: {:x}", sk);
            println!("Public key: {:x}", pk);
            println!("Wallet Address: {}", addr);
        }
        _ => {}
    }
}
