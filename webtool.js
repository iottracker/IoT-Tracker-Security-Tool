// Wrap everything in an IIFE to avoid global scope pollution
(function() {
    // Create required elements if they don't exist
    function createRequiredElements() {
        const requiredElements = [
            { id: 'welcome-text', type: 'div' },
            { id: 'intro-text', type: 'div' },
            { id: 'download-full-scan', type: 'div' },
            { id: 'background-scan-status', type: 'div' },
            { id: 'scan-status-content', type: 'div' },
            { id: 'scan-status-header', type: 'div' }
        ];

        requiredElements.forEach(elem => {
            if (!document.getElementById(elem.id)) {
                const element = document.createElement(elem.type);
                element.id = elem.id;
                element.style.display = 'none';
                document.body.appendChild(element);
                console.log(`Created missing ${elem.id} element`);
            }
        });

        // Create get-started button if it doesn't exist
        if (!document.querySelector('.get-started-btn')) {
            const btn = document.createElement('button');
            btn.className = 'get-started-btn';
            btn.style.display = 'none';
            document.body.appendChild(btn);
        }
    }

    // Safe element getter
    function safeGetElement(id) {
        return document.getElementById(id) || { 
            addEventListener: () => {},
            innerHTML: '',
            style: {},
            value: ''
        };
    }

    // Main initialization
    document.addEventListener('DOMContentLoaded', function() {
        createRequiredElements();
        initializeUserInterface();
        setupEventListeners();
    });

    function initializeUserInterface() {
        // Update Username Functionality
        const updateUsernameButton = safeGetElement('update-username-button');
        const newUsernameInput = safeGetElement('new-username');
        const updateStatus = safeGetElement('update-username-status');

        if (updateUsernameButton) {
            updateUsernameButton.addEventListener('click', function() {
                const newUsername = newUsernameInput.value.trim();
                if (!newUsername) {
                    updateStatus.textContent = "Please enter a valid username.";
                    updateStatus.style.color = "red";
                    updateStatus.style.display = "block";
                    return;
                }

                updateUsername(newUsername, updateStatus);
            });
        }

        // Change Password Functionality
        const changePasswordButton = safeGetElement('change-password-button');
        const updatePasswordButton = safeGetElement('update-password-button');
        const passwordForm = safeGetElement('password-form');

        if (changePasswordButton) {
            changePasswordButton.addEventListener('click', function() {
                passwordForm.style.display = "block";
            });
        }

        if (updatePasswordButton) {
            updatePasswordButton.addEventListener('click', function() {
                handlePasswordUpdate(passwordForm);
            });
        }
    }

    // Network functionality
    function getLocalIP(callback) {
        try {
            const pc = new RTCPeerConnection({ iceServers: [] });
            pc.createDataChannel("");
            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(err => console.log('Error creating offer:', err));

            pc.onicecandidate = (event) => {
                if (event && event.candidate) {
                    const ipMatch = event.candidate.candidate.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
                    if (ipMatch) {
                        callback(ipMatch[1]);
                    } else {
                        callback("Not Available");
                    }
                    pc.close();
                }
            };
        } catch (e) {
            console.log('Error getting local IP:', e);
            callback("Not Available");
        }
    }

    // Map functionality
    let mapInitialized = false;

    function initializeMap() {
        if (!mapInitialized && document.getElementById('map')) {
            mapInitialized = true;
            try {
                const map = L.map('map').setView([51.505, -0.09], 13);

                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '&copy; OpenStreetMap contributors'
                }).addTo(map);

                if (navigator.geolocation) {
                    navigator.geolocation.getCurrentPosition(
                        function(position) {
                            handleGeolocationSuccess(position, map);
                        },
                        function() {
                            console.log("Unable to retrieve location");
                        }
                    );
                }
            } catch (e) {
                console.log('Error initializing map:', e);
            }
        }
    }

    function handleGeolocationSuccess(position, map) {
        const userLat = position.coords.latitude;
        const userLng = position.coords.longitude;

        getLocalIP((privateIp) => {
            const currentTime = new Date().toLocaleString();
            const message = `
                <strong>You are here!</strong><br>
                🔒 Private IP: ${privateIp}<br>
                ⏰ Time: ${currentTime}
            `;

            map.setView([userLat, userLng], 13);
            L.marker([userLat, userLng])
                .addTo(map)
                .bindPopup(message)
                .openPopup();
        });
    }

    // Network scanning functionality
    function setupNetworkScanning() {
        const scanNetworkButton = safeGetElement('scan-network-button');
        const networkInput = safeGetElement('network-range');
        const devicesList = safeGetElement('devices-list');

        if (scanNetworkButton) {
            scanNetworkButton.addEventListener('click', function(event) {
                event.preventDefault();
                handleNetworkScan(networkInput, devicesList);
            });
        }
    }

    function handleNetworkScan(networkInput, devicesList) {
        const network = networkInput.value.trim();
        if (!network) {
            alert("Please enter a valid network range.");
            return;
        }

        fetch('/scan_network', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ network: network }),
        })
        .then(response => response.json())
        .then(devices => updateDevicesList(devices, devicesList))
        .catch(error => {
            console.error('Error scanning network:', error);
            alert('Error scanning network. Please try again.');
        });
    }

    function updateDevicesList(devices, devicesList) {
        devicesList.innerHTML = '';
        
        if (Array.isArray(devices) && devices.length > 0) {
            devices.forEach(device => {
                const deviceInfo = document.createElement('div');
                deviceInfo.className = 'device-info';
                deviceInfo.innerHTML = `
                    <p><strong>IP Address:</strong> ${device.ip}</p>
                    <p><strong>MAC Address:</strong> ${device.mac}</p>
                    <p><strong>Manufacturer:</strong> ${device.manufacturer}</p>
                    <p><strong>Open Ports:</strong> ${device.open_ports.join(', ') || 'None'}</p>
                    <hr>
                `;
                devicesList.appendChild(deviceInfo);
            });
        } else {
            devicesList.innerHTML = '<p>No devices found in the network range.</p>';
        }
    }

    // Vulnerability scanning functionality
    function setupVulnerabilityScanning() {
        const scanVulnsButton = safeGetElement('scan-vulns-button');
        const vulnIpInput = safeGetElement('vuln-ip-input');
        const vulnsList = safeGetElement('vulns-list');

        if (scanVulnsButton) {
            scanVulnsButton.addEventListener('click', function() {
                handleVulnerabilityScan(vulnIpInput, vulnsList);
            });
        }
    }

    function handleVulnerabilityScan(vulnIpInput, vulnsList) {
        const ip = vulnIpInput.value.trim();
        if (!ip) {
            alert("Please enter a valid IP address.");
            return;
        }

        fetch('/scan_vulnerabilities', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        })
        .then(response => response.json())
        .then(vulnerabilities => {
            vulnsList.innerHTML = vulnerabilities.map(vuln => `
                <li>Port: ${vuln.port}, Service: ${vuln.service}, State: ${vuln.state}</li>
            `).join('');
        })
        .catch(error => alert("Error scanning vulnerabilities: " + error));
    }

    // Traffic analysis functionality
    function setupTrafficAnalysis() {
        const analyzeTrafficButton = safeGetElement('analyze-traffic-button');
        const trafficIpInput = safeGetElement('traffic-ip-input');
        const trafficList = safeGetElement('traffic-list');

        if (analyzeTrafficButton) {
            analyzeTrafficButton.addEventListener('click', function() {
                handleTrafficAnalysis(trafficIpInput, trafficList);
            });
        }
    }

    function handleTrafficAnalysis(trafficIpInput, trafficList) {
        const ip = trafficIpInput.value.trim();
        if (!ip) {
            alert("Please enter a valid IP address.");
            return;
        }

        fetch('/analyze_traffic', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        })
        .then(response => response.json())
        .then(trafficData => {
            trafficList.innerHTML = trafficData.map(traffic => `
                <li>Source: ${traffic.source}, Destination: ${traffic.destination}, Protocol: ${traffic.protocol}, Length: ${traffic.length}</li>
            `).join('');
        })
        .catch(error => alert("Error analyzing traffic: " + error));
    }

    // Tab switching functionality
    function setupTabSwitching() {
        document.querySelectorAll('.tab-button').forEach((button) => {
            button.addEventListener('click', () => {
                const tabId = button.dataset.tab;
                handleTabSwitch(tabId, button);
            });
        });

        // Initialize map if "Explorer" tab is active by default
        if (document.getElementById('explorer')?.classList.contains('active')) {
            initializeMap();
        }
    }

    function handleTabSwitch(tabId, button) {
        // Clear active classes
        document.querySelectorAll('.tab-button').forEach((btn) => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach((content) => content.classList.remove('active'));

        // Activate the selected tab
        button.classList.add('active');
        document.getElementById(tabId)?.classList.add('active');

        // Initialize the map if the Explorer tab is selected
        if (tabId === 'explorer') {
            initializeMap();
        }
    }

    // Welcome text functionality - made safe
    const welcomeText = "Welcome To IoT Tracker";
    const introText = "Your Trusted Tool To Discover, Analyze And Find Vulnerability.";
    let welcomeTypingIndex = 0;
    let introTypingIndex = 0;

    function typeWelcomeText() {
        const welcomeElement = safeGetElement('welcome-text');
        if (welcomeTypingIndex < welcomeText.length) {
            welcomeElement.innerHTML += welcomeText.charAt(welcomeTypingIndex);
            welcomeTypingIndex++;
            setTimeout(typeWelcomeText, 100);
        } else {
            typeIntroText();
        }
    }

    function typeIntroText() {
        const introElement = safeGetElement('intro-text');
        const getStartedBtn = document.querySelector('.get-started-btn');
        
        if (introTypingIndex < introText.length) {
            introElement.innerHTML += introText.charAt(introTypingIndex);
            introTypingIndex++;
            setTimeout(typeIntroText, 100);
        } else if (getStartedBtn) {
            getStartedBtn.style.display = 'block';
            getStartedBtn.style.opacity = '1';
            getStartedBtn.style.transition = 'opacity 5s ease';
        }
    }

    // Setup all event listeners
    function setupEventListeners() {
        setupNetworkScanning();
        setupVulnerabilityScanning();
        setupTrafficAnalysis();
        setupTabSwitching();

        // Get Started button click handler
        const getStartedBtn = document.querySelector('.get-started-btn');
        if (getStartedBtn) {
            getStartedBtn.addEventListener('click', () => {
                window.location.href = 'getstarted.html';
            });
        }
    }

    // Start the welcome text animation if elements exist
    if (document.getElementById('welcome-text')) {
        window.onload = typeWelcomeText;
    }

})();
