fn load_parameterized_qualification_fragment() {
    macro_rules! invoke_include {
        ($macro_name:ident) => {
            $macro_name!("parameterized_qualification.inc");
        };
    }

    invoke_include!(include);
}

fn main() {}
