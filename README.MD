# bcrypt-bench

> Automatically figure out the optimal bcrypt salt rounds for your hardware.

This module will find the optimal bcrypt salt rounds by performing hash operations to gauge hardware performance. This
can allow your apps to automatically adapt to hardware changes without manual intervention.

The optimal value is a compromise between speed and security. The higher it is set, the better the security, however the
operation time grows exponentially. It should be set as high as is tolerable for your particular application.

For more information see the [bcrypt module documentation](https://www.npmjs.com/package/bcrypt#a-note-on-rounds).

## Usage

The module exports a single function. This function will set or overwrite an environment variable `BCRYPT_SALT`,
which is accessible by `process.env.BCRYPT_SALT`. In addition, the optimal value will be returned by the function as an
integer.

### Configuration

There are some optional configuration values which may be supplied by environment variables and/or by passing an object
to the function.

The precedent is as follows:

1. The function will first look in the object optionally supplied as the first function parameter.
2. If not present, it will check for an environment variable *(if applicable)*.
3. If neither are present, it will use the default value.

|  Option        |  Env. Variable       | Default | Description |
| :------------: | :------------------: | :-----: | ----------- |
| `minSalt`      | `BCRYPT_SALT`        | 10      | The absolute minimum salt to use, regardless of maxHashTime. The tests will increment from this level. The env. variable will be set or overwritten during the tests.
| `maxHashTime`  | `BCRYPT_MAXHASHTIME` | 250     | Target time-per-hash in milliseconds. Different applications have different requirements, so set this to the maximum yours should tolerate.
| `epochs`       |                      | 3       | Number of hash operations to perform for each salt value. The higher the number, the more accurate the test will be - but it will take longer. 
| `quickFactor`  |                      | 90      | Set between 0 - 100. Controls how aggressively techniques are applied to speed up the process. Higher values may be less accurate. Set this to 0 or set `quick: false` instead to disable this feature.
| `quiet`        |                      | false   | Prevents console logging.

### Basic example

```
const {hashSync} = require("bcrypt");
const bcryptBench = require("bcrypt-bench");

const options = {
  minSalt: 12,
  maxHashTime: 500
};

const salt = bcryptTest(options);

hashSync("abcdef", salt);
```

### Example with .env

**.env**

```
BCRYPT_SALT        = 12
BCRYPT_MAXHASHTIME = 250
```

**index.js**

```
const dotenv = require("dotenv");
const {hashSync} = require("bcrypt");
const bcryptBench = require("bcrypt-bench");

dotenv.config();

if (process.env.NODE_ENV === "production") {

  const options = {
    maxHashTime: 500 // Overrides value from .env
  };

  bcryptTest(options);
}

hashSync("abcdef", Number(process.env.BCRYPT_SALT)); // Env. vars are strings and will upset bcrypt
```
