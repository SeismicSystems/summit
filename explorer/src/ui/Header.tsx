import React, { useState } from "react";
import AboutModal from "../AboutModal";
import KeyInfoModal from "../KeyModal";
import SearchModal from "../SearchModal";
import { PUBLIC_KEY_HEX } from "../config";

export default function Header() {
  const [isSearchModalOpen, setIsSearchModalOpen] = useState<boolean>(false);
  const [isKeyInfoModalOpen, setIsKeyInfoModalOpen] = useState<boolean>(false);
  const [isAboutModalOpen, setIsAboutModalOpen] = useState<boolean>(false);

  return (
    <>
      <div className="logo-container">
        <div className="svg-logo">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="40"
            height="37"
            viewBox="0 0 31 29"
            fill="none"
          >
            <path
              fillRule="evenodd"
              clipRule="evenodd"
              d="M6.35297 2.2688C9.68945 2.2688 12.8391 3.63008 15.1079 5.99676C17.3767 3.63008 20.5264 2.2688 23.8629 2.2688H29.0944C30.5358 2.2688 30.6425 0 29.0944 0H23.8629C20.6776 0 17.608 1.04989 15.1079 2.96281C12.6167 1.04989 9.54709 0 6.35297 0H1.12141C-0.426712 0 -0.319945 2.2688 1.12141 2.2688H6.35297ZM6.12131 11.2688C4.67105 11.2688 4.58208 9 6.12131 9C13.0167 9 13.0167 19.7657 6.12131 19.7657C4.58208 19.7657 4.67105 17.4969 6.12131 17.4969C10.0361 17.4969 10.0361 11.2599 6.12131 11.2599V11.2688ZM24.1715 11.2688C25.6218 11.2688 25.7108 9 24.1715 9C17.2762 9 17.2762 19.7657 24.1715 19.7657C25.7108 19.7657 25.6218 17.4969 24.1715 17.4969C20.2567 17.4969 20.2567 11.2599 24.1715 11.2599V11.2688ZM24.2226 24.7786H26.8562C28.3954 24.7786 28.2887 22.5277 26.8562 22.5277H24.2404C14.4801 22.5277 14.4801 7.25098 24.2404 7.25098H26.8562C28.2887 7.25098 28.3954 5 26.8562 5H24.2226C21.5356 5 18.9821 6.10324 17.1137 8.03395L15.4854 9.72445L13.8572 8.03395C11.9977 6.09434 9.43528 5 6.7483 5H4.11474C2.57551 5 2.68228 7.25098 4.11474 7.25098H6.73055C16.4909 7.25098 16.4909 22.5277 6.73055 22.5277H4.11474C2.68228 22.5277 2.57551 24.7786 4.11474 24.7786H6.7483C9.43528 24.7786 11.9888 23.6754 13.8572 21.7447L15.4854 20.0542L17.1137 21.7447C18.9732 23.6843 21.5356 24.7786 24.2226 24.7786ZM6.35297 26.728C9.68945 26.728 12.8391 25.3667 15.1079 23C17.3767 25.3667 20.5264 26.728 23.8629 26.728H29.0944C30.5358 26.728 30.6425 28.9968 29.0944 28.9968H23.8629C20.6776 28.9968 17.608 27.9469 15.1079 26.0339C12.6167 27.9469 9.54709 28.9968 6.35297 28.9968H1.12141C-0.426712 28.9968 -0.319945 26.728 1.12141 26.728H6.35297Z"
              fill="currentColor"
            />
          </svg>
        </div>
        <div className="logo-text-container">
          <span className="logo-text">Seismic</span>
        </div>
      </div>
      <div className="about-button-container">
        <button
          className="search-header-button"
          onClick={() => setIsSearchModalOpen(true)}
        >
          ⚲
        </button>
        <button
          className="key-header-button"
          onClick={() => setIsKeyInfoModalOpen(true)}
        >
          ⚷︎
        </button>
        <button
          className="about-header-button"
          onClick={() => setIsAboutModalOpen(true)}
        >
          ?︎
        </button>
      </div>

      <AboutModal
        isOpen={isAboutModalOpen}
        onClose={() => setIsAboutModalOpen(false)}
      />
      <KeyInfoModal
        isOpen={isKeyInfoModalOpen}
        onClose={() => setIsKeyInfoModalOpen(false)}
        publicKeyHex={PUBLIC_KEY_HEX}
      />
      <SearchModal
        isOpen={isSearchModalOpen}
        onClose={() => setIsSearchModalOpen(false)}
      />
    </>
  );
}
