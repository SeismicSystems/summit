import { colors } from './colors'


export const fonts = {
    mono: 'IBM Plex Mono, monospace',
    sans: 'Suisse Intl, sans-serif',
    sansWorks: 'Suisse Intl Works, sans-serif',
    monoTitle: 'GT America Mono Bold, monospace',
} as const

export const typography = {
    // Headers using GT America Mono Bold
    h1: {
        fontFamily: fonts.monoTitle,
        fontSize: '2.5rem',
        fontWeight: 700,
        lineHeight: 1.2,
        color: colors.primary,
    },
    h2: {
        fontFamily: fonts.monoTitle,
        fontSize: '2rem',
        fontWeight: 700,
        lineHeight: 1.3,
        color: colors.primary,
    },
    h3: {
        fontFamily: fonts.sans,
        fontSize: '1.5rem',
        fontWeight: 600,
        lineHeight: 1.4,
        color: colors.textSecondary,
    },

    // Body text using Suisse Intl
    body1: {
        fontFamily: fonts.sans,
        fontSize: '1rem',
        fontWeight: 400,
        lineHeight: 1.6,
        color: colors.text,
    },
    body2: {
        fontFamily: fonts.sans,
        fontSize: '0.875rem',
        fontWeight: 400,
        lineHeight: 1.5,
        color: colors.text,
    },

    // Technical/code text using IBM Plex Mono
    code: {
        fontFamily: fonts.mono,
        fontSize: '0.875rem',
        fontWeight: 400,
        lineHeight: 1.4,
        color: colors.textSecondary,
    },

    // UI elements using Suisse Intl Works
    button: {
        fontFamily: fonts.sansWorks,
        fontSize: '0.875rem',
        fontWeight: 500,
        lineHeight: 1.2,
        textTransform: 'uppercase' as const,
        letterSpacing: '0.05em',
    },
    caption: {
        fontFamily: fonts.sansWorks,
        fontSize: '0.75rem',
        fontWeight: 400,
        lineHeight: 1.4,
        color: colors.textSecondary,
    },
} as const