use crate::{Client, Error, IndexQuery};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::simplex::types::{View, Viewable as _};
use futures::{Stream, StreamExt, channel::mpsc::unbounded};
use seismicbft_types::{Finalized, Kind, NAMESPACE, Notarized, Seed};
use tokio_tungstenite::{connect_async, tungstenite::Message as TMessage};

fn seed_upload_path(base: String) -> String {
    format!("{}/seed", base)
}

fn notarization_upload_path(base: String) -> String {
    format!("{}/notarization", base)
}

fn notarization_get_path(base: String, query: &IndexQuery) -> String {
    format!("{}/notarization/{}", base, query.serialize())
}

fn finalization_upload_path(base: String) -> String {
    format!("{}/finalization", base)
}

fn finalization_get_path(base: String, query: &IndexQuery) -> String {
    format!("{}/finalization/{}", base, query.serialize())
}

fn listen_path(base: String) -> String {
    format!("{}/consensus/ws", base)
}

pub enum Message {
    Seed(Seed),
    Notarization(Notarized),
    Finalization(Finalized),
}

impl Client {
    pub async fn seed_upload(&self, seed: Seed) -> Result<(), Error> {
        let result = self
            .client
            .post(seed_upload_path(self.uri.clone()))
            .body(seed.view.encode().to_vec())
            .send()
            .await
            .map_err(Error::Reqwest)?;
        if !result.status().is_success() {
            return Err(Error::Failed(result.status()));
        }
        Ok(())
    }
    pub async fn notarized_upload(&self, notarized: Notarized) -> Result<(), Error> {
        let result = self
            .client
            .post(notarization_upload_path(self.uri.clone()))
            .body(notarized.encode().to_vec())
            .send()
            .await
            .map_err(Error::Reqwest)?;
        if !result.status().is_success() {
            return Err(Error::Failed(result.status()));
        }
        Ok(())
    }

    pub async fn notarized_get(&self, query: IndexQuery) -> Result<Notarized, Error> {
        // Get the notarization
        let result = self
            .client
            .get(notarization_get_path(self.uri.clone(), &query))
            .send()
            .await
            .map_err(Error::Reqwest)?;
        if !result.status().is_success() {
            return Err(Error::Failed(result.status()));
        }
        let bytes = result.bytes().await.map_err(Error::Reqwest)?;
        let notarized = Notarized::decode(bytes.as_ref()).map_err(Error::InvalidData)?;
        if !notarized.proof.verify(NAMESPACE, &self.participants) {
            return Err(Error::InvalidSignature);
        }

        // Verify the notarization matches the query
        match query {
            IndexQuery::Latest => {}
            IndexQuery::Index(index) => {
                if notarized.proof.view() != index {
                    return Err(Error::UnexpectedResponse);
                }
            }
        }
        Ok(notarized)
    }

    pub async fn finalized_upload(&self, finalized: Finalized) -> Result<(), Error> {
        let result = self
            .client
            .post(finalization_upload_path(self.uri.clone()))
            .body(finalized.encode().to_vec())
            .send()
            .await
            .map_err(Error::Reqwest)?;
        if !result.status().is_success() {
            return Err(Error::Failed(result.status()));
        }
        Ok(())
    }

    pub async fn finalized_get(&self, query: IndexQuery) -> Result<Finalized, Error> {
        // Get the finalization
        let result = self
            .client
            .get(finalization_get_path(self.uri.clone(), &query))
            .send()
            .await
            .map_err(Error::Reqwest)?;
        if !result.status().is_success() {
            return Err(Error::Failed(result.status()));
        }
        let bytes = result.bytes().await.map_err(Error::Reqwest)?;
        let finalized = Finalized::decode(bytes.as_ref()).map_err(Error::InvalidData)?;
        if !finalized.proof.verify(NAMESPACE, &self.participants) {
            return Err(Error::InvalidSignature);
        }

        // Verify the finalization matches the query
        match query {
            IndexQuery::Latest => {}
            IndexQuery::Index(index) => {
                if finalized.proof.view() != index {
                    return Err(Error::UnexpectedResponse);
                }
            }
        }
        Ok(finalized)
    }

    pub async fn listen(&self) -> Result<impl Stream<Item = Result<Message, Error>>, Error> {
        // Connect to the websocket endpoint
        let (stream, _) = connect_async(listen_path(self.ws_uri.clone()))
            .await
            .map_err(Error::from)?;
        let (_, read) = stream.split();

        // Create an unbounded channel for streaming consensus messages
        let (sender, receiver) = unbounded();
        tokio::spawn({
            let participants = self.participants.clone();
            async move {
                read.for_each(|message| async {
                    match message {
                        Ok(TMessage::Binary(data)) => {
                            // Get kind
                            let kind = data[0];
                            let Some(kind) = Kind::from_u8(kind) else {
                                let _ = sender.unbounded_send(Err(Error::UnexpectedResponse));
                                return;
                            };
                            let data = &data[1..];

                            // Deserialize the message
                            match kind {
                                Kind::Seed => {
                                    let result = View::decode(data);

                                    match result {
                                        Ok(view) => {
                                            let _ = sender
                                                .unbounded_send(Ok(Message::Seed(Seed { view })));
                                        }
                                        Err(e) => {
                                            let _ =
                                                sender.unbounded_send(Err(Error::InvalidData(e)));
                                        }
                                    }
                                }
                                Kind::Notarization => {
                                    let result = Notarized::decode(data);
                                    match result {
                                        Ok(notarized) => {
                                            if !notarized.proof.verify(NAMESPACE, &participants) {
                                                let _ = sender
                                                    .unbounded_send(Err(Error::InvalidSignature));
                                            }
                                            let _ = sender.unbounded_send(Ok(
                                                Message::Notarization(notarized),
                                            ));
                                        }
                                        Err(e) => {
                                            let _ =
                                                sender.unbounded_send(Err(Error::InvalidData(e)));
                                        }
                                    }
                                }
                                Kind::Finalization => {
                                    let result = Finalized::decode(data);
                                    match result {
                                        Ok(finalized) => {
                                            if !finalized.proof.verify(NAMESPACE, &participants) {
                                                let _ = sender
                                                    .unbounded_send(Err(Error::InvalidSignature));
                                                return;
                                            }
                                            let _ = sender.unbounded_send(Ok(
                                                Message::Finalization(finalized),
                                            ));
                                        }
                                        Err(e) => {
                                            let _ =
                                                sender.unbounded_send(Err(Error::InvalidData(e)));
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => {} // Ignore non-binary messages.
                        Err(e) => {
                            let _ = sender.unbounded_send(Err(Error::from(e)));
                        }
                    }
                })
                .await;
            }
        });
        Ok(receiver)
    }
}
