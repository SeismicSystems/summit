
import { atom, Getter, Setter } from 'jotai'

export type ModalType = 'about' | 'keyInfo' | 'search' | null

export const activeModalAtom = atom<ModalType>(null)

// Action atoms for opening/closing modals
export const openModalAtom = atom(null, (get: Getter, set: Setter, modalType: ModalType) => {
    set(activeModalAtom, modalType)
})

export const closeModalAtom = atom(null, (get: Getter, set: Setter) => {
    set(activeModalAtom, null)
})

// Convenience atoms for checking specific modals
export const isAboutModalOpenAtom = atom((get: Getter) => get(activeModalAtom) === 'about')
export const isKeyInfoModalOpenAtom = atom((get: Getter) => get(activeModalAtom) === 'keyInfo')
export const isSearchModalOpenAtom = atom((get: Getter) => get(activeModalAtom) === 'search')
