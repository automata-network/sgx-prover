pub fn debug<T: std::fmt::Debug>(d: T) -> String {
    format!("{:?}", d)
}