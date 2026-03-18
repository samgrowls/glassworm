//! Confusables Module
//!
//! This module provides confusable character detection for homoglyph attacks.

pub mod data;

pub use data::{
    get_base_char, get_confusable_script, get_confusables, get_similarity, is_confusable,
    ConfusableEntry,
};
