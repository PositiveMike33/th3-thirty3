import React, { useEffect, useState, forwardRef, useImperativeHandle } from 'react';

const WWTMapComponent = forwardRef((props, ref) => {
    const [wwtControl, setWwtControl] = useState(null);
    const [initialized, setInitialized] = useState(false);

    // Provide methods to parent
    useImperativeHandle(ref, () => ({
        // This method will be called when Astrometry.net solves an image
        addSolvedImage: (imageUrl, calibration) => {
            if (!wwtControl) {
                console.error("WWT Control not initialized");
                return;
            }
            console.log("Adding solved image:", imageUrl, calibration);

            try {
                // Calculation of parameters from Astrometry.net calibration
                // Calibration usually has: ra, dec (degrees), radius (deg), pixscale (arcsec/pixel), orientation (deg), parity
                // WWT needs: CenterX (RA), CenterY (Dec in deg), Rotation (deg), Scale (deg/pixel)

                const centerX = calibration.ra;
                const centerY = calibration.dec;
                const rotation = calibration.orientation || 0; // check sign?
                const scale = (calibration.pixscale || 1) / 3600; // arcsec -> deg

                // We need image dimensions. 
                // Since we don't have them easily from calibration API alone without another call, 
                // we might need them passed in or default. 
                // However, WWT creates an ImageSet. 
                // Let's rely on WWT to handle generic image set creation if possible, 
                // or we use a helper. 

                // For now, let's try setting the view to the location at least!
                wwtControl.gotoRaDecZoom(centerX, centerY, calibration.radius * 2, false);

                // TODO: To properly overlay the image, we need to create a WWT Imageset.
                // This requires constructing the ImageSet object or loading a WTML.
                // Since Astrometry provides a WTML link: https://nova.astrometry.net/api/jobs/[JOBID]/wtml
                // We should probably use that!

                if (calibration.wtml_url) {
                    wwtControl.loadImageCollection(calibration.wtml_url);
                } else {
                    console.warn("No WTML URL provided in calibration");
                }

            } catch (e) {
                console.error("Error adding image to WWT", e);
            }
        }
    }));

    useEffect(() => {
        const startTime = Date.now();
        const initWWT = () => {
            if (typeof window.wwtLib === 'undefined') {
                // Check timeout (20s)
                if (Date.now() - startTime > 20000) {
                    console.error("WWT Script load timeout");
                    return;
                }
                setTimeout(initWWT, 500); // Poll slower
                return;
            }

            try {
                // Initialize the WWT Control
                // "WWTCanvas" must match the div ID
                const control = window.wwtLib.WWTControl.initControl("WWTCanvas");

                // Default settings
                control.settings.set_showConstellationFigures(false);
                control.settings.set_showCrosshairs(true);
                control.settings.set_showConstellationBoundaries(false);

                // Hide UI elements we don't want (SDK usually is plain canvas)
                // Set default background
                control.setBackgroundImageByName("Digitized Sky Survey (Color)");

                setWwtControl(control);
                setInitialized(true);
                console.log("WWT SDK Initialized");
            } catch (error) {
                console.error("WWT Init Failed:", error);
            }
        };

        initWWT();
    }, []);

    return (
        <div className="w-full h-full bg-black relative">
            <div
                id="WWTCanvas"
                style={{
                    width: '100%',
                    height: '100%',
                    backgroundColor: 'black'
                }}
            />

            {/* Loading Indicator */}
            {!initialized && (
                <div className="absolute inset-0 flex items-center justify-center text-cyan-500">
                    Initializing Universe...
                </div>
            )}
        </div>
    );
});

export default WWTMapComponent;
