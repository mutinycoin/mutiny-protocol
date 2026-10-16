//! Checked, outward integer arithmetic. Selected values are inputs, never defaults.
use super::{Error,Result};
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) struct Interval {pub(super) lower:u64,pub(super) upper:u64}
impl Interval {
    pub(super) fn new(lower:u64,upper:u64)->Result<Self> {
        if lower>upper {return Err(Error::Arithmetic);}Ok(Self{lower,upper})
    }
    pub(super) fn duration(start:Self,end:Self)->Result<Self> {
        Self::new(end.lower.checked_sub(start.upper).ok_or(Error::Arithmetic)?,
            end.upper.checked_sub(start.lower).ok_or(Error::Arithmetic)?)
    }
    pub(super) fn widen(self,quantum:u64)->Result<Self> {
        if quantum==0{return Err(Error::Arithmetic);}
        Self::new(self.lower.checked_sub(quantum).ok_or(Error::Arithmetic)?,
            self.upper.checked_add(quantum).ok_or(Error::Arithmetic)?)
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) struct Ratio {pub(super) numerator:u64,pub(super) denominator:u64}
impl Ratio {
    pub(super) fn new(numerator:u64,denominator:u64)->Result<Self> {
        if denominator==0 || numerator>denominator{return Err(Error::Arithmetic);}
        Ok(Self{numerator,denominator})
    }
    fn reduced(self)->Self {
        let(mut a,mut b)=(self.numerator,self.denominator);
        while b!=0 {(a,b)=(b,a%b);}let divisor=a.max(1);
        Self{numerator:self.numerator/divisor,denominator:self.denominator/divisor}
    }
    pub(super) fn add(self,other:Self)->Result<Self> {
        let(mut a,mut b)=(self.denominator,other.denominator);
        while b!=0 {(a,b)=(b,a%b);}let g=a;
        let left=other.denominator/g;let right=self.denominator/g;
        let numerator=u128::from(self.numerator).checked_mul(u128::from(left))
            .and_then(|n|n.checked_add(u128::from(other.numerator)*u128::from(right))).ok_or(Error::Arithmetic)?;
        let denominator=u128::from(self.denominator).checked_mul(u128::from(left)).ok_or(Error::Arithmetic)?;
        Self::new(u64::try_from(numerator).map_err(|_|Error::Arithmetic)?,
            u64::try_from(denominator).map_err(|_|Error::Arithmetic)?).map(Self::reduced)
    }
    pub(super) fn at_most(self,other:Self)->bool {
        u128::from(self.numerator)*u128::from(other.denominator)
            <=u128::from(other.numerator)*u128::from(self.denominator)
    }
}
pub(super) fn ceil_div(n:u128,d:u128)->Result<u64> {
    if d==0{return Err(Error::Arithmetic);}let value=n/d+u128::from(n%d!=0);
    u64::try_from(value).map_err(|_|Error::Arithmetic)
}
/// All FOUR endpoint combinations; scalar counter measurements are insufficient.
pub(super) fn frequency_upper(counter:Interval,reference:Interval,minimum_ns:u64)->Result<u64> {
    if counter.lower==0 || reference.lower==0 || reference.lower<minimum_ns{return Err(Error::Arithmetic);}
    let mut bound=0;
    for c in [counter.lower,counter.upper] {for r in [reference.lower,reference.upper] {
        bound=bound.max(ceil_div(u128::from(c.abs_diff(r))*1_000_000_000,u128::from(r))?);
    }}Ok(bound)
}
pub(super) fn check_margin(measured:u64,selected_drift:u64,margin:Ratio)->Result<u64> {
    let reserved=ceil_div(u128::from(selected_drift)*u128::from(margin.numerator),u128::from(margin.denominator))?;
    if measured.checked_add(reserved).ok_or(Error::Arithmetic)?>selected_drift{return Err(Error::Frequency);}
    Ok(reserved)
}
pub(super) fn precision_ns(exponent:i64)->Result<u64> {
    // NTP signed precision octet; decimal printed records must preserve this exact value.
    if !(-128..=127).contains(&exponent){return Err(Error::Precision);}
    if exponent>=0 {
        let factor=1u128.checked_shl(exponent as u32).ok_or(Error::Arithmetic)?;
        let value=1_000_000_000u128.checked_mul(factor).ok_or(Error::Arithmetic)?;
        u64::try_from(value).map_err(|_|Error::Arithmetic)
    } else {
        let shift=u32::try_from(-exponent).map_err(|_|Error::Arithmetic)?;
        if shift>=128 {return Ok(1);}ceil_div(1_000_000_000,1u128<<shift)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn modeled_four_corner_frequency_and_outward_margin() {
        let i=Interval::new(999_999_900,1_000_000_100).unwrap();
        assert_eq!(frequency_upper(i,Interval::new(1_000_000_000,1_000_000_000).unwrap(),1).unwrap(),100);
        assert!(frequency_upper(i,Interval::new(0,1).unwrap(),1).is_err());
        assert_eq!(check_margin(6944,8680,Ratio::new(1,5).unwrap()).unwrap(),1736);
        assert!(check_margin(6945,8680,Ratio::new(1,5).unwrap()).is_err());
    }
    #[test] fn modeled_union_sum_does_not_assume_independence_or_wrap() {
        let a=Ratio::new(1,2000).unwrap();assert_eq!(a.add(a).unwrap(),Ratio::new(1,1000).unwrap());
        assert!(a.add(a).unwrap().at_most(Ratio::new(1,1000).unwrap()));
        assert!(Ratio::new(1,u64::MAX).unwrap().add(Ratio::new(1,u64::MAX-1).unwrap()).is_err());
        assert!(Interval::duration(Interval::new(10,20).unwrap(),Interval::new(19,30).unwrap()).is_err());
    }
    #[test] fn modeled_positive_precision_octet_never_truncates_to_zero() {
        assert_eq!(precision_ns(0),Ok(1_000_000_000));
        assert_eq!(precision_ns(34),Ok(17_179_869_184_000_000_000));
        for exponent in [35,100,127]{assert_eq!(precision_ns(exponent),Err(Error::Arithmetic));}
        assert_eq!(precision_ns(-128),Ok(1));
    }
}
