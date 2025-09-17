import React from "react";

function Footer() {
  return (
    <div>
      {" "}
      <div className="socials">
        <a href="https://docs.seismic.systems">Docs</a>
        <a href="https://github.com/seismic-systems">GitHub</a>
        <a href="https://discord.gg/seismic">Discord</a>
        <a href="https://t.me/seismicsystems">Telegram</a>
      </div>
      &copy; {new Date().getFullYear()} Seismic Systems. All rights reserved.
    </div>
  );
}

export default Footer;
