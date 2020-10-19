use std::ops::{Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive};

/// An object-safe version of `std::ops::RangeBounds`.
pub trait DynRangeBounds<T>
where
    T: std::cmp::PartialOrd,
{
    fn contains(&self, item: &T) -> bool;
}

impl<T> DynRangeBounds<T> for Box<dyn DynRangeBounds<T>>
where
    T: std::cmp::PartialOrd,
{
    fn contains(&self, item: &T) -> bool {
        (**self).contains(item)
    }
}

macro_rules! impl_dynrange {
    ($($range:ident),*) => {$(
        impl<T> DynRangeBounds<T> for $range<T>
            where T: std::cmp::PartialOrd
        {
            fn contains(&self, item: &T) -> bool {
               $range::contains(self, item)
            }
        }
    )*};
}

impl_dynrange!(Range, RangeFrom, RangeTo, RangeToInclusive, RangeInclusive);

// RangeFull doesn't have a generic parameter associated with it.
impl<T> DynRangeBounds<T> for RangeFull
where
    T: std::cmp::PartialOrd,
{
    fn contains(&self, _item: &T) -> bool {
        true
    }
}
