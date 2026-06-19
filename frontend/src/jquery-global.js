// Expose jQuery on `window` BEFORE any jQuery plugin imports run.
// ESM evaluates dependency modules in post-order, so importing this file
// first from main.js guarantees window.$/window.jQuery exist by the time
// DataTables and other plugins are imported.
import $ from 'jquery';

window.$ = $;
window.jQuery = $;

export default $;
