//! Heat palette + color-mode resolution.
//!
//! Single hot/cool ramp keyed off `intensity = value / max_in_section`.
//! When `colored = false` every helper returns the empty `Style`, so call
//! sites can `palette.X().style(text)` unconditionally.

use std::io::IsTerminal;

use owo_colors::Style;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl ColorMode {
    /// Resolve to a concrete on/off, honoring `NO_COLOR` and `IsTerminal`.
    pub fn resolve(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                if std::env::var_os("NO_COLOR").is_some() {
                    return false;
                }
                std::io::stdout().is_terminal()
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub colored: bool,
}

impl Palette {
    pub fn new(colored: bool) -> Self {
        Self { colored }
    }

    /// Heat ramp for `intensity` in `[0.0, 1.0]`. Higher = hotter.
    pub fn heat(self, intensity: f64) -> Style {
        if !self.colored {
            return Style::new();
        }
        if intensity >= 0.6 {
            Style::new().red().bold()
        } else if intensity >= 0.3 {
            Style::new().bright_red()
        } else if intensity >= 0.1 {
            Style::new().yellow()
        } else if intensity > 0.0 {
            Style::new()
        } else {
            Style::new().bright_black()
        }
    }

    pub fn dim(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().bright_black()
    }

    pub fn bold(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().bold()
    }

    /// Function names.
    pub fn function(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().cyan()
    }

    /// File paths and `file:line` locations.
    pub fn path(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().bright_black()
    }

    /// Section / table headers.
    pub fn header(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().bold().underline()
    }
}
