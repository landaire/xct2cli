//! Heat palette + color-mode resolution. Helpers return an empty
//! `Style` when `colored = false`, so call sites can use them
//! unconditionally.

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
    /// Honors `NO_COLOR` and stdout's `IsTerminal`.
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

    /// Heat ramp for `intensity` in `[0.0, 1.0]`. Higher is hotter.
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

    pub fn function(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().cyan()
    }

    pub fn path(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().bright_black()
    }

    pub fn header(self) -> Style {
        if !self.colored {
            return Style::new();
        }
        Style::new().bold().underline()
    }

    /// Stable color per hot-line index so the same line gets the same
    /// color in the asm overlay and the source snippet. Skips red (heat
    /// owns it) and grey (dim/path owns it). Truecolor; owo-colors
    /// falls back to nearest 256-color when needed.
    pub fn line_marker(self, index: usize) -> Style {
        if !self.colored {
            return Style::new();
        }
        const PALETTE: &[(u8, u8, u8)] = &[
            (0x4d, 0xb8, 0xff),
            (0xff, 0x6b, 0x9d),
            (0xa3, 0xe6, 0x35),
            (0xff, 0xa6, 0x4d),
            (0xc2, 0x9b, 0xff),
            (0x6b, 0xff, 0xea),
            (0xff, 0xd7, 0x00),
            (0x4d, 0xe6, 0xa6),
            (0xe6, 0x5b, 0xb7),
            (0x6b, 0x5b, 0xe6),
        ];
        let (r, g, b) = PALETTE[index % PALETTE.len()];
        Style::new().truecolor(r, g, b).bold()
    }
}
