import React from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import { LatLng, DivIcon } from "leaflet";
import "leaflet/dist/leaflet.css";
import { LOCATIONS } from "../config";
import MapOverlay from "../MapOverlay";
import { ViewData } from "../types";

const center = new LatLng(37.7749, -122.4194);
const markerIcon = new DivIcon({
  className: "custom-div-icon",
  html: `<div style="
      background-color: #0000eeff;
      width: 16px;
      height: 16px;
      border-radius: 50%;
    "></div>`,
  iconSize: [12, 12],
  iconAnchor: [6, 6],
});

function MapComponent({ views }: { views: ViewData[] }) {
  return (
    <div className="map-container">
      <MapContainer
        center={center}
        zoom={1}
        style={{ height: "100%", width: "100%" }}
        zoomControl={false}
        scrollWheelZoom={false}
        doubleClickZoom={false}
        touchZoom={false}
        dragging={false}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/light_nolabels/{z}/{x}/{y}{r}.png"
          attribution="&copy; OSM | &copy; CARTO</a>"
        />
        {views.length > 0 && views[0].location !== undefined && (
          <Marker
            key={views[0].view}
            position={views[0].location}
            icon={markerIcon}
          >
            <Popup>
              <div>
                <strong>View: {views[0].view}</strong>
                <br />
                Location: {views[0].locationName}
                <br />
                Status: {views[0].status}
                <br />
                {views[0].block && (
                  <>
                    Block Height: {views[0].block.height}
                    <br />
                  </>
                )}
                {views[0].startTime && (
                  <>
                    Start Time:{" "}
                    {new Date(views[0].startTime).toLocaleTimeString()}
                    <br />
                  </>
                )}
              </div>
            </Popup>
          </Marker>
        )}
        <MapOverlay numValidators={LOCATIONS.length} />
      </MapContainer>
    </div>
  );
}

export default MapComponent;
