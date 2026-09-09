#[path = "custom_module.rs"]
mod custom_module;

include!("direct_qualification.inc");

macro_rules! load_qualification_fragment {
    () => {
        include!("qualification.inc");
    };
}

load_qualification_fragment!();

fn load_local_qualification_fragment() {
    macro_rules! load_local_qualification {
        () => {
            include!("local_qualification.inc");
        };
    }

    load_local_qualification!();
}

fn main() {}
