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

/**
 * For the given x, y pairs computes the parameters of a line mx + b that
 * minimizes quadratic error. This problem can be phrased as follows:
 *
 * y⃑ = A w⃑
 *
 * where y⃑ is the vector with all y-coordinates, A is a n x 2 matrix
 * containing ones in the first column (for the bias term) and the vector
 * of all x-coordinates in the second column, and w⃑ is the 2 x 1 vector
 * (b, m).
 *
 * Now, the regularised least squares solution for this problem is
 *
 * w⃑ = (A^T A + λI)^-1 A^T y⃑
 *
 * The matrix A^T A is a 2 x 2 matrix, so the inverse is trivial to compute.
 *
 * @param xs: array of x-values.
 * @param ys: array of y-values.
 * @return b, m, rmse
 */
function linear_regression(xs, ys) {
	// Compute A^T A, track the maximum and minimum value in xs
	if ((!xs.length) || (!ys.length) || (xs.length !== ys.length)) {
		throw "xs and ys must be arrays and have the same non-zero length";
	}
	let n = xs.length;
	let a11 = n + 0.0, a12 = 0.0, a22 = 0.0; // a21 = a12
	for (let i = 0; i < n; i++) {
		a12 += xs[i] + 0.0;
		a22 += xs[i] * xs[i] + 0.0;
	}

	// Invert A
	let det = a11 * a22 - a12 * a12;
	let ai11 = a22 / det, ai22 = a11 / det, ai12 = -a12 / det;

	// Compute A^T y⃑
	let aty1 = 0.0, aty2 = 0.0;
	for (let i = 0; i < n; i++) {
		aty1 += ys[i];
		aty2 += ys[i] * xs[i];
	}

	// Compute w⃑ = (A^T A + λI)^-1 A^T y⃑
	const b = ai11 * aty1 + ai12 * aty2;
	const m = ai12 * aty1 + ai22 * aty2;

	return [b, m];
}


function build_timeseries_for_endpoint(idx, interval, time, data) {
	const res = [[], []];

	// Processes data within one connection sequence
	function push_cs(buf, last_sst, last_ls) {
		// We need at least two data points for each connection sequence.
		// Otherwise the least-squares won't work.
		if (buf.length < 2) {
			return [0.0, last_ls];
		}

		// Compute the average round-trip-time. We'll use this for outlier
		// detection.
		let rtt_accu = 0.0;
		for (let i = 0; i < buf.length; i++) {
			const sst = buf[i].sst, srt = buf[i].srt;
			rtt_accu += (srt - sst);
		}
		const rtt_avg = rtt_accu / buf.length;

		// Fit a line to the client timestamps vs. the server timestamps using
		// least squares. This way we can map client-side timestamps to
		// server-side timestamps and approximate the TX and RX latency.
		const xs = [], ys = []
		const crt0 = buf[0].crt;
		const sst0 = buf[0].sst;
		for (let i = 0; i < buf.length; i++) {
			const crt = buf[i].crt, sst = buf[i].sst, srt = buf[i].srt;
			const rtt = srt - sst;
			if (rtt < 2.0 * rtt_avg) {
				xs.push(crt - crt0);
				ys.push(sst + 0.5 * (srt - sst) - sst0);
			}
		}
		let [offs, drift] = linear_regression(xs, ys);

		// Iterate over the buffer again, this time computing the tx latency,
		// the rx latency, as well as the corresponding time. If there is a gap
		// in the local sequence number "ls", insert a gap into the chart
		for (let i = 0; i < buf.length; i++) {
			// Fetch the "server client receive time", the "server send time",
			// and the "server receive time"
			const scrt = drift * (buf[i].crt - crt0) + offs + sst0;
			const sst = buf[i].sst, srt = buf[i].srt;
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
		}
		return [rtt_accu, last_ls];
	};

	// Extract all entries with the same connection sequence number
	const N_max = (600.0 / interval) | 0;
	let last_ls = 0;
	let last_cs = 0;
	let last_sst = null;
	let rtt_accu = 0.0, rtt_accu_batch = 0.0;
	let buf = [];
	for (let i = 0; i < data.length; i++) {
		if (data[i].i != idx) {
			continue;
		}
		if ((data[i].cs != last_cs) || ((buf.length > N_max) && (data.length - i > N_max / 2))) {
			[rtt_accu_batch, last_ls] = push_cs(buf, last_sst, last_ls);
			rtt_accu += rtt_accu_batch;
			last_sst = data[i].sst;
			buf = [];
			last_cs = data[i].cs;
		}
		buf.push(data[i])
	}
	[rtt_accu_batch, last_ls] = push_cs(buf, last_sst, last_ls);
	rtt_accu += rtt_accu_batch;
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
			// Create the divs for the chart
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

			// Extract the time series from the raw data
			const [rtt_avg, timeseries] = build_timeseries_for_endpoint(idx, data.interval, data.time, data.data);
			if (timeseries[0].length < 2) {
				div_chart.innerText = "Not enough data yet.";
				continue;
			}

			const main = new MG.LineChart({
				"data": timeseries,
				"width": 1200,
				"height": 300,
				"target": "#chart_" + idx,
				"legend": ['TX Latency', 'RTT Latency'],
				"yAxis": {"label": "Latency (ms)"},
				"yScale": {"minValue": 0, "maxValue": rtt_avg * 5000.0},
				"area": true,
				"missing_is_hidden": true,
			});
			idx++;
		}
	});
});
})();
