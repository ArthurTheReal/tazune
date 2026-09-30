use thiserror::Error;


#[derive(Error, Debug)]
pub enum TazuneError {
    #[error("Reached the end of buffer with length of {buffer_length}")]
    EndOfBufferReached {buffer_length: usize},

    #[error("index out of range, the allowed range is [{range_start}:{range_end}]")]
    IndexOutOfRange {range_start: usize, range_end: usize},

    #[error("maximum number of jumps performed during parsing the query name")]
    MaxJumpsPerformed,

    
}