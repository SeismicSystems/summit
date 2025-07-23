import React, { useEffect } from 'react';

interface AboutModalProps {
    isOpen: boolean;
    onClose: () => void;
}

const AboutModal: React.FC<AboutModalProps> = ({ isOpen, onClose }) => {
    // Add effect to handle link targets
    useEffect(() => {
        if (isOpen) {
            // Find all links in the modal and set them to open in new tabs
            const modalLinks = document.querySelectorAll('.about-modal a');
            modalLinks.forEach(link => {
                if (link instanceof HTMLAnchorElement) {
                    link.setAttribute('target', '_blank');
                    link.setAttribute('rel', 'noopener noreferrer');
                }
            });
        }
    }, [isOpen]);
    if (!isOpen) return null;

    return (
        <div className="about-modal-overlay">
            <div className="about-modal">
                <div className="about-modal-header">
                    <h2>Welcome to the Seismic Explorer!</h2>
                </div>
                <div className="about-modal-content">
                    <section>
                        <h3>About</h3>
                        <p>
                            This explorer visualizes the real-time consensus performance of Seismic, an encrypted blockchain,
                            deployed on a cluster of globally distributed nodes.
                        </p>
                        <p>
                            <i>Seismic is designed for privacy-preserving applications with built-in encryption capabilities.</i>
                        </p>
                    </section>

                    <section>
                        <h3>What is Seismic?</h3>
                        <p>
                            <a href="https://www.seismic.systems">Seismic</a> is an encrypted blockchain that provides privacy and security for decentralized applications.
                        </p>
                        <p>
                            Seismic focuses on delivering fast, secure, and private blockchain infrastructure for the next generation of decentralized applications.
                        </p>
                    </section>

                    <section>
                        <h3>What are you looking at?</h3>
                        <p>
                            This explorer displays the progression of Seismic's consensus protocol over time, broken into <strong>views</strong>.
                        </p>
                        <p>
                            Validators coordinate to agree on blocks through a multi-phase process. Each view represents a round of consensus
                            where validators work together to finalize the next block in the chain.
                        </p>
                        <p>
                            We color the phases of consensus as follows:
                        </p>
                        <ul className="status-list">
                            <li>
                                <div className="status-indicator-wrapper">
                                    <div className="about-status-indicator" style={{ backgroundColor: "#4da6ff" }}></div>
                                    <strong>Seeded</strong>
                                </div>
                                A leader has been selected to propose a block. The dot on the map shows the region where the leader is located.
                                A new leader is elected for each view.
                            </li>
                            <li>
                                <div className="status-indicator-wrapper">
                                    <div className="about-status-indicator" style={{ backgroundColor: "#ffffff" }}></div>
                                    <strong>Locked</strong>
                                </div>
                                The proposed block has received sufficient votes from validators and is locked in for this view.
                            </li>
                            <li>
                                <div className="status-indicator-wrapper">
                                    <div className="about-status-indicator" style={{ backgroundColor: "#228B22ff" }}></div>
                                    <strong>Finalized</strong>
                                </div>
                                The block has been finalized and is now permanently part of the blockchain.
                            </li>
                        </ul>
                    </section>
                    <section>
                        <h3>Why is it so fast?</h3>
                        <p>
                            Seismic uses advanced consensus algorithms designed for high performance and low latency,
                            allowing validators to quickly agree on new blocks while maintaining security and decentralization.
                        </p>
                        <p>
                            The consensus protocol employs efficient communication patterns between validators, ensuring
                            that blocks are processed and finalized as quickly as network conditions allow.
                        </p>
                    </section>
                    <section>
                        <h3>Network Information</h3>
                        <p>
                            This explorer displays data from Seismic's consensus network, showing real-time progression
                            of blocks through the validation and finalization process.
                        </p>
                        <p>
                            The data is streamed in real-time, providing an authentic view of the network's performance
                            and consensus behavior as it happens.
                        </p>
                    </section>
                    <section>
                        <h3>Learn More</h3>
                        <p>
                            Visit <a href="https://www.seismic.systems">seismic.systems</a> to learn more about the project,
                            read the documentation, and get involved with the community.
                        </p>
                    </section>
                    <section>
                        <h3>Support</h3>
                        <p>Join our community on <a href="https://discord.gg/seismic">Discord</a> or <a href="https://t.me/seismicsystems">Telegram</a> for support and discussions!</p>
                    </section>
                </div>
                <div className="about-modal-footer">
                    <button className="about-button" onClick={onClose}>Close</button>
                </div>
            </div>
        </div >
    );
};

export default AboutModal;