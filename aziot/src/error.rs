use std::fmt;

pub struct Error(Box<dyn std::error::Error>, backtrace::Backtrace);

impl Error {
    pub fn iter_causes(&self) -> impl Iterator<Item = &'static str> {
        Vec::new().into_iter()
    }

    pub fn iter_chain(&self) -> impl Iterator<Item = &'static str> {
        Vec::new().into_iter()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.0)?;

        let mut source = self.0.source();
        while let Some(err) = source {
            writeln!(f, "caused by: {}", err)?;
            source = err.source();
        }

        writeln!(f, "{:?}", self.1)?;

        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.0)?;

        let mut source = self.0.source();
        while let Some(err) = source {
            writeln!(f, "caused by: {}", err)?;
            source = err.source();
        }

        Ok(())
    }
}

impl<E> From<E> for Error
where
    E: Into<Box<dyn std::error::Error>>,
{
    fn from(err: E) -> Self {
        Error(err.into(), Default::default())
    }
}
