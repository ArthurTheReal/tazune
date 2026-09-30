use thiserror::Error;


#[derive(Error, Debug)]
pub enum TazuneError {
    #[error("Reached the end of buffer with length of {buffer_length}")]
    EndOfBufferReached {buffer_length: usize},

    #[error("index out of range, the allowed range is [{range_start}:{range_end}]")]
    IndexOutOfRange {range_start: usize, range_end: usize},

    #[error("maximum number of jumps performed during parsing the query name")]
    MaxJumpsPerformed,

    #[error("invalid lable type in query name section: {label_type}")]
    InvalidLabelType {label_type: u8},

    #[error("query name is too long, max length is {max_name_len} but a name with length of {name_len} was encountered")]
    QNameTooLong {max_name_len: usize, name_len: usize}
}