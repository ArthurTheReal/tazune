use thiserror::Error;

#[derive(Error, Debug)]
pub enum TazuneError {
    #[error("Reached the end of buffer with length of {buffer_length}")]
    EndOfBufferReached { buffer_length: usize },

    #[error("index out of range, the allowed range is [{range_start}:{range_end}]")]
    IndexOutOfRange {
        range_start: usize,
        range_end: usize,
    },

    #[error("maximum number of jumps performed during parsing the query name")]
    MaxJumpsPerformed,

    #[error("invalid label type in query name section: {label_type}")]
    InvalidLabelType { label_type: u8 },

    #[error(
        "query name is too long, max length is {max_name_len} but a name with length of {name_len} was encountered"
    )]
    QNameTooLong {
        max_name_len: usize,
        name_len: usize,
    },

    #[error(
        "label too long, a single label can be up to 63 characters long, but a label with length of {label_len} was encountered"
    )]
    LabelTooLong { label_len: usize },

    #[error("response id {received} does not match the query id {expected}")]
    IdMismatch { expected: u16, received: u16 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
