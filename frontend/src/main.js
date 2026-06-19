// Vite entry — replaces the CDN tags that used to live in templates/index.html.
// Import order matters: jQuery must be on `window` before DataTables loads.

import './jquery-global.js';

import * as bootstrap from 'bootstrap';
window.bootstrap = bootstrap;

import 'datatables.net-bs5';

import Chart from 'chart.js/auto';
window.Chart = Chart;

// vis-network — flow graph view (B.6). The /standalone entry bundles vis-data,
// so the Network/DataSet pair is available without a second top-level dep
// (we kept vis-data in package.json only as a peer-dep marker).
import { Network, DataSet } from 'vis-network/standalone';
import 'vis-network/styles/vis-network.css';
window.visNetwork = { Network, DataSet };

// Stylesheets (Vite extracts to a single CSS file in production).
import 'bootstrap/dist/css/bootstrap.min.css';
import 'datatables.net-bs5/css/dataTables.bootstrap5.min.css';
import '@fortawesome/fontawesome-free/css/all.min.css';
import './style.css';

// Existing application code. It still relies on jQuery/Bootstrap/Chart
// being available as globals — those were set up above — and it exposes
// its inline-handler functions onto `window` at the bottom of the file.
import './app.js';
