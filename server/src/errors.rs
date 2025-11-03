use std::{error::Error, fmt};

#[derive(Debug)]
pub struct NoAddressLeft;

impl Error for NoAddressLeft {}

impl fmt::Display for NoAddressLeft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No addresses remaining in range")
    }
}
