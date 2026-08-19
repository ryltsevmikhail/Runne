use std::{
    fmt,
    fs::File,
    io::{self, Cursor, Read},
    path::Path,
};

use aho_corasick::{AhoCorasick, BuildError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Direct #[path] integration targets compile this shared support separately.
#[allow(dead_code)]
pub enum RepresentationClass {
    Raw,
    Base64,
    Base64Unpadded,
    Base64Url,
    LowerHex,
    UpperHex,
}

#[derive(Clone)]
pub struct SecretRepresentation {
    pub class: RepresentationClass,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchMetadata {
    pub pattern_id: usize,
    pub representation_class: RepresentationClass,
}

pub enum ScanError {
    EmptyPatternSet,
    EmptyPattern {
        input_index: usize,
        class: RepresentationClass,
    },
    MatcherBuild(BuildError),
    Io {
        kind: io::ErrorKind,
    },
    MatcherMetadata {
        pattern_id: usize,
    },
}

impl fmt::Display for RepresentationClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPatternSet => formatter.write_str("protected scan has no patterns"),
            Self::EmptyPattern { input_index, class } => write!(
                formatter,
                "protected scan has empty pattern input_index={input_index} class={class}"
            ),
            Self::MatcherBuild(error) => {
                let _ = error;
                formatter.write_str("protected scan matcher build failed")
            }
            Self::Io { kind } => write!(formatter, "protected scan I/O failed: {kind:?}"),
            Self::MatcherMetadata { pattern_id } => write!(
                formatter,
                "protected scan matcher metadata missing pattern_id={pattern_id}"
            ),
        }
    }
}

pub struct SecretScanner {
    matcher: AhoCorasick,
    classes_by_pattern: Vec<RepresentationClass>,
}

impl SecretScanner {
    pub fn new(representations: Vec<SecretRepresentation>) -> Result<Self, ScanError> {
        if representations.is_empty() {
            return Err(ScanError::EmptyPatternSet);
        }

        let mut bytes = Vec::new();
        let mut classes_by_pattern = Vec::new();
        for (input_index, representation) in representations.into_iter().enumerate() {
            if representation.bytes.is_empty() {
                return Err(ScanError::EmptyPattern {
                    input_index,
                    class: representation.class,
                });
            }
            if !bytes
                .iter()
                .any(|existing: &Vec<u8>| existing == &representation.bytes)
            {
                classes_by_pattern.push(representation.class);
                bytes.push(representation.bytes);
            }
        }

        let matcher = AhoCorasick::new(bytes).map_err(ScanError::MatcherBuild)?;
        Ok(Self {
            matcher,
            classes_by_pattern,
        })
    }

    pub fn scan_reader<R: Read>(&self, reader: R) -> Result<Option<MatchMetadata>, ScanError> {
        let mut first_match = None;
        for result in self.matcher.stream_find_iter(reader) {
            let matched = result.map_err(|error| ScanError::Io { kind: error.kind() })?;
            if first_match.is_none() {
                let pattern_id = matched.pattern().as_usize();
                let representation_class = *self
                    .classes_by_pattern
                    .get(pattern_id)
                    .ok_or(ScanError::MatcherMetadata { pattern_id })?;
                first_match = Some(MatchMetadata {
                    pattern_id,
                    representation_class,
                });
            }
        }
        Ok(first_match)
    }
}

// Direct #[path] integration targets compile this shared support separately.
#[allow(dead_code)]
pub fn assert_reader_absent<R: Read>(scanner: &SecretScanner, sink: &str, reader: R) {
    match scanner.scan_reader(reader) {
        Ok(Some(metadata)) => panic!(
            "{sink} contained protected material: pattern_id={} representation_class={}",
            metadata.pattern_id, metadata.representation_class
        ),
        Ok(None) => {}
        Err(ScanError::Io { kind }) => panic!("{sink} protected scan failed: {kind:?}"),
        Err(_) => panic!("{sink} protected scan failed"),
    }
}

fn path_label(scanner: &SecretScanner, path: &Path) -> String {
    let Some(path_str) = path.to_str() else {
        return "<unavailable-path>".to_owned();
    };
    match scanner.scan_reader(Cursor::new(path_str.as_bytes())) {
        Ok(Some(_)) => "<protected-path>".to_owned(),
        Ok(None) => path_str.to_owned(),
        Err(_) => "<unavailable-path>".to_owned(),
    }
}

pub fn assert_file_absent(scanner: &SecretScanner, sink: &str, path: &Path) {
    let label = path_label(scanner, path);
    let file = File::open(path)
        .unwrap_or_else(|error| panic!("{sink} protected scan failed: {label} {:?}", error.kind()));
    match scanner.scan_reader(file) {
        Ok(Some(metadata)) => panic!(
            "{sink} contained protected material: {label} pattern_id={} representation_class={}",
            metadata.pattern_id, metadata.representation_class
        ),
        Ok(None) => {}
        Err(ScanError::Io { kind }) => panic!("{sink} protected scan failed: {label} {kind:?}"),
        Err(_) => panic!("{sink} protected scan failed: {label}"),
    }
}
