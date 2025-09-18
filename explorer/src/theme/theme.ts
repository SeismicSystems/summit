import { colors } from "./colors"
import { typography, fonts } from "./typography"

export const theme = {
    colors,
    typography,



} as const

export type Theme = typeof theme
export type Colors = typeof colors
export type Typography = typeof typography

// CSS Custom Properties (for use in CSS files)
export const cssVariables = `
    :root {
      /* Colors */
      --color-dark-brown: ${colors.darkBrown};
      --color-mid-brown: ${colors.midBrown};
      --color-lite-brown: ${colors.liteBrown};
      --color-white: ${colors.white};
      --color-black: ${colors.black};
      
      --color-primary: ${colors.primary};
      --color-secondary: ${colors.secondary};
      --color-accent: ${colors.accent};
      --color-background: ${colors.background};
      --color-text: ${colors.text};
      
      /* Fonts */
      --font-mono: ${fonts.mono};
      --font-sans: ${fonts.sans};
      --font-sans-works: ${fonts.sansWorks};
      --font-mono-title: ${fonts.monoTitle};
      
 
    }
  `