/*
 *  Latency Monitor
 *  Copyright (C) 2020  Andreas Stöckel
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

(function () {
"use strict";

async function fetch_json(url) {
	const response = await fetch(url);
	return response.json()
}

async function load_data() {
	let res = await Promise.all([
		fetch_json('api/data'),
		fetch_json('api/time'),
		fetch_json('api/endpoints'),
		fetch_json('api/interval'),
	]);
	return {
		"data": res[0],
		"time": res[1],
		"endpoints": res[2],
		"interval": res[3],
	};
}

function build_timeseries_for_endpoint(idx, interval, time, data) {
	const res = [[], []];

	// Processes data within one connection sequence
	function push_cs(buf) {
		// We need at least two data points for each connection sequence.
		// Otherwise the least-squares won't work.
		if (buf.length < 2) {
			return 0.0;
		}

		// Fit a line to the client timestamps vs. the server timestamps using
		// least squares. This way we can map client-side timestamps to
		// server-side timestamps and approximate the TX and RX latency.
		const xs = [], ys = []
		let offs = 0;
		for (let i = 0; i < buf.length; i++) {
			const crt = buf[i].crt, sst = buf[i].sst, srt = buf[i].srt;
			offs += 0.5 * ((sst - crt) + (srt - crt));
		}
		offs /= buf.length;
		rtt_accu = 0.0;

		// Iterate over the buffer again, this time computing the tx latency,
		// the rx latency, as well as the corresponding time. If there is a gap
		// in the local sequence number "ls", insert a gap into the chart
		let last_ls = 0;
		for (let i = 0; i < buf.length; i++) {
			// Fetch the "server client receive time", the "server send time",
			// and the "server receive time"
			const scrt = buf[i].crt + offs, sst = buf[i].sst, srt = buf[i].srt;
			const rtt_latency = Math.round((srt - sst) * 100000.0) / 100.0;
			const tx_latency = Math.round(((scrt > sst) ? scrt - sst : 0.0) * 100000.0) / 100.0;

			// Compute the unix timestamp corresponding to the server send time
			const t = new Date((sst - time.monotonic + time.unix) * 1000.0);

			// Insert a dummy datapoint if there is a gap in the sequence number
			if ((last_ls + 1 !== buf[i].ls) && (last_sst !== null)) {
				const gap_t = new Date((last_sst - time.monotonic + time.unix + interval) * 1000.0);
				for (let i = 0; i < 2; i++) {
					res[i].push({
						"date": gap_t,
						"value": null,
					});
				}
			}

			// Add the TX latency and RTT latency to the dataset
			res[0].push({
				"date": t,
				"value": tx_latency,
			});
			res[1].push({
				"date": t,
				"value": rtt_latency,
			});

			// Remember the last local sequence number
			last_ls = buf[i].ls;
			last_sst = sst;

			// Accumulate the average
			rtt_accu+= rtt_latency;
		}
		return rtt_accu;
	}

	// Extract all entries with the same connection sequence number
	let last_cs = 0;
	let last_sst = null;
	let rtt_accu= 0.0;
	let buf = [];
	for (let i = 0; i < data.length; i++) {
		if (data[i].i != idx) {
			continue;
		}
		if (data[i].cs != last_cs) {
			rtt_accu += push_cs(buf, last_sst);
			last_sst = data[i].sst;
			buf = [];
			last_cs = data[i].cs;
		}
		buf.push(data[i])
	}
	rtt_accu += push_cs(buf, last_sst);
	return [rtt_accu / data.length, res];
}

window.addEventListener("load", function() {
	// Fetch all data, then plot it
	load_data().then((data) => {
		// Remove the "loading" div
		const div_loading = document.querySelector(".loading");
		div_loading.parentNode.removeChild(div_loading);

		// Fetch the chart container
		const div_charts = document.getElementById("charts");

		// For each endpoint, build a series of timestamp, latency tx, latency rx
		// datapoints. Plot the data into the frame
		let idx = 0;
		for (let endpoint of data.endpoints) {
			// Extract the time series from the raw data
			const [rtt_avg, timeseries] = build_timeseries_for_endpoint(idx, data.interval, data.time, data.data);
			console.log(rtt_avg, endpoint);

			// Create two divs for the time
			const div_chart_cntr = document.createElement("div");
			const h1_header = document.createElement("h1");
			const div_chart = document.createElement("div");
			h1_header.innerText = endpoint;
			div_chart.setAttribute("id", "chart_" + idx);

			div_chart_cntr.classList.add("chart_cntr");
			div_chart.classList.add("chart");
			div_chart_cntr.appendChild(h1_header);
			div_chart_cntr.appendChild(div_chart);
			div_charts.appendChild(div_chart_cntr);

			const main = new MG.LineChart({
				"data": timeseries,
				"width": 600,
				"height": 200,
				"top": 200,
				"bottom": 0,
				"target": "#chart_" + idx,
				"legend": ['TX Latency', 'RTT Latency'],
				"yAxis": {"label": "Latency (ms)"},
				"yScale": {"minValue": 0, "maxValue": rtt_avg * 5.0},
				"area": true,
				"missing_is_hidden": true,
			});
			idx++;
		}
	});
});
})();
