import {randomBytes} from "crypto";
import {hashSync} from "bcrypt";

export default options => {

	options = Object.assign({
		minSalt: Number(process.env.BCRYPT_SALT) ?? 10,
		maxHashTime: Number(process.env.BCRYPT_MAXHASHTIME ?? 250),
		epochs: 3,
		quick: true,
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

	while (++currSalt) {
		let time = 0;
		for (let i = 0; i < options.epochs; i++) time += test(currSalt);
		time /= options.epochs;
		if (time > options.maxHashTime) return fin();
		prevTime = time;
		process.env.BCRYPT_SALT = currSalt.toString();
		if (!options.quiet) console.log(`  > Increased BCRYPT_SALT to ${currSalt}.`);
		if (options.quick && time > options.maxHashTime * 0.65) return fin();
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
