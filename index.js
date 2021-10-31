import {randomBytes} from "crypto";
import {hashSync} from "bcrypt";

export default options => {

	options = Object.assign({
		quick: true,
		quiet: false
	}, options ?? {});

	if (!options.quiet) console.log("> Performing bcrypt tests...");

	process.env.BCRYPT_SALT = String(options.minSalt ?? process.env.BCRYPT_SALT ?? 10);

	if (!options.quiet) console.log(`  > BCRYPT_SALT set to ${process.env.BCRYPT_SALT}.`);

	let currSalt = Number(process.env.BCRYPT_SALT);
	const maxTime = Number(options.maxHashTime ?? process.env.BCRYPT_MAX_HASHTIME ?? 250);
	const epochs = 5;

	while (++currSalt) {
		const arr = [];
		for (let i = 0; i < epochs; i++) arr.push(randomBytes(16).toString());
		const start = Date.now();
		for (let i = 0; i < epochs; i++) hashSync(arr[i], currSalt);
		const time = (Date.now() - start) / epochs;
		if (time > maxTime) return fin();
		if (!options.quiet) console.log(`  > Increased BCRYPT_SALT to ${(process.env.BCRYPT_SALT = currSalt.toString())}.`);
		if (options.quick && time > maxTime * 0.7) return fin();
	}

	function fin() {
		console.log();
		return Number(process.env.BCRYPT_SALT);
	}
};
