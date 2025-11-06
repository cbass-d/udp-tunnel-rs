use std::{error::Error, fmt};

#[derive(Debug)]
pub struct UnexpectedSource;

impl Error for UnexpectedSource {}

impl fmt::Display for UnexpectedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unexpected source in message received")
    }
}

#[derive(Debug)]
pub struct UnexpectedMessage;

impl Error for UnexpectedMessage {}

impl fmt::Display for UnexpectedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unexpected message received")
    }
}
