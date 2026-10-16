// The --bin TEST harness compiles these exact private application modules with
// cfg(test), so finite positive dispatch can use its scoped TEST installation.
// Ordinary executable compilation always uses the ordinary library instead.
#[cfg(test)] include!("treasury_application_modules_v1.rs");
fn main(){
    let args:Vec<String>=std::env::args().skip(1).collect();
    let mut input=std::io::stdin().lock();
    #[cfg(not(test))] let outcome=mutiny_native_treasury_application::application_main(&args,&mut input);
    #[cfg(test)] let outcome=application_main(&args,&mut input);
    if let Err(refusal)=outcome{eprintln!("TREASURY_APPLICATION_DISABLED: {refusal:?}");std::process::exit(78);}
}
