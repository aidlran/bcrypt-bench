import {randomBytes} from "crypto";
import {hashSync} from "bcrypt";

export default options => {

	(() => {
		checkProperties(process.env, ["BCRYPT_SALT", "BCRYPT_MAXHASHTIME"]);
		if (options) {
			if (options.quickFactor > 100) resetProperty(options, "quickFactor");
			checkProperties(options, ["minSalt", "maxHashTime", "epochs"]);
		}
		function resetProperty(params, property) {
			delete params[property];
			process.emitWarning(`Invalid ${params === process.env? "process.env." : ""}${property} value.`, {
				code: "BCRYPT_TEST"
			});
		}
		function checkProperties(params, properties) {
			properties.forEach(property => {
				if (params[property] && Number(params[property]) < 1) resetProperty(params, property);
			});
		};
	})();

	options = Object.assign({
		minSalt: Number(process.env.BCRYPT_SALT ?? 10),
		maxHashTime: Number(process.env.BCRYPT_MAXHASHTIME ?? 250),
		epochs: 3,
		quickFactor: (options && options.quick === false) ? 0 : 90,
		quiet: false
	}, options ?? {});

	if (!options.quiet) console.log(`> Performing bcrypt tests (Target: ${options.maxHashTime}ms)`);

	process.env.BCRYPT_SALT = String(options.minSalt);

	if (!options.quiet) console.log(`  > BCRYPT_SALT set to ${process.env.BCRYPT_SALT}.`);

	let currSalt = Number(options.minSalt);
	let prevTime = test(currSalt);
	if (prevTime > options.maxHashTime) {
		process.emitWarning(`Minimum salt rounds (${options.minSalt}, ${prevTime}ms) exceeds target of ${options.maxHashTime}ms.`, {
			code: "BCRYPT_TEST"
		});
		return fin();
	}

	options.quickFactor = options.quickFactor / 100 * 0.45;

	(() => {
		const skippyTarget = options.maxHashTime * options.quickFactor;
		let skippy = prevTime;
		while ((skippy += skippy) < skippyTarget) currSalt += 1;
	})();

	const speedierTarget = options.maxHashTime * (1 - options.quickFactor);

	while (++currSalt) {
		let time = 0;
		for (let i = 0; i < options.epochs; i++) time += test(currSalt);
		time /= options.epochs;
		if (time > options.maxHashTime) return fin();
		prevTime = time;
		process.env.BCRYPT_SALT = currSalt.toString();
		if (!options.quiet) console.log(`  > Increased BCRYPT_SALT to ${currSalt}.`);
		if (time > speedierTarget) return fin();
	}

	function test(salt) {
		const data = randomBytes(16).toString();
		const start = Date.now();
		hashSync(data, salt);
		return Date.now() - start;
	}

	function fin() {
		if (!options.quiet) console.log(`> Done. Using ${process.env.BCRYPT_SALT} salt rounds at approx. ${Math.floor(prevTime)}ms per hash.\n`);
		return Number(process.env.BCRYPT_SALT);
	}
};
