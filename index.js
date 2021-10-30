import {randomBytes} from "crypto";
import {hashSync} from "bcrypt";

export default options => {

	options = Object.assign({
		quick: true
	}, options ?? {});

	console.log("> Performing bcrypt tests...");

	process.env.BCRYPT_SALT = String(options.minSalt ?? process.env.BCRYPT_SALT ?? 10);

	console.log(`  > BCRYPT_SALT set to ${process.env.BCRYPT_SALT}.`);

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
		console.log(`  > Increased BCRYPT_SALT to ${(process.env.BCRYPT_SALT = currSalt.toString())}.`);
		if (options.quick && time > maxTime * 0.7) return fin();
	}

	function fin() {
		console.log();
		return Number(process.env.BCRYPT_SALT);
	}
};
