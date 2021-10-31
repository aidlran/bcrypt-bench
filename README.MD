# bcrypt-test

> Automatically get the optimal bcrypt work factor (rounds) for your hardware.

This module will find the optimal bcrypt work factor by performing hash operations until the completion time gets too
high. This can allow your apps to automatically adapt to hardware changes without manual intervention.

The optimal work factor is a compromise between speed and security. The higher it is set, the better the security,
however the operation time grows exponentially. It should be set as high as is tolerable for your particular
application. As an example, while it would be nice to use a large number for hashed user passwords, consideration needs
to be made for the user experience.

## Usage

The module exports a single function. The function will set or overwrite an environment variable `BCRYPT_SALT`,
which is accessible by `process.env.BCRYPT_SALT`. In addition, the optimal value will be returned by the function as an
integer.

There are some optional configuration values which may be supplied by environment variables or by passing an object
parameter to the function. The precedent is as follows:

1. The function will first look in the object optionally supplied as the first function parameter.
2. If not present, it will check for an environment variable *(if applicable)*.
3. If neither are present, it will use the default value.

|  Option        |  Env. Variable       | Default | Description |
| :------------: | :------------------: | :-----: | ----------- |
| `minSalt`      | `BCRYPT_SALT`        | 10      | The absolute minimum salt to use, regardless of maxHashTime. The tests will increment from this level. The env. variable will be set or overwritten during the test.
| `maxHashTime`  | `BCRYPT_MAXHASHTIME` | 250     | Target hash time in milliseconds. Different applications have different requirements, so set this to the maximum yours should tolerate.
| `epochs`       |                      | 3       | Number of times to test each salt round value. The higher the number the more accurate the result at the cost of speed. 
| `quick`        |                      | true    | Speeds up the process - will conclude upon finding a salt level that gets very near maxHashTime as it can be assumed that the following test will surpass it.
| `quiet`        |                      | false   | Prevents console logging.

# Examples

***NOTE:** Using `"type": "module"` in package.json.*

## Basic usage

```
import {hashSync} from 'bcrypt';
import bcryptTest from 'bcrypt-test';

const options = {
  minSalt: 12,
  maxHashTime: 500
};

const salt = bcryptTest(options);

hashSync("abcdef", salt);
```

## With Dotenv

**.env**
```
BCRYPT_SALT         = 12
BCRYPT_MAX_HASHTIME = 250
```

**.js**
```
import dotenv from 'dotenv';
import {hashSync} from 'bcrypt';
import bcryptTest from 'bcrypt-test';

dotenv.config();

if (process.env.NODE_ENV === "production") {

  const options = {
    maxHashTime: 500 // Overrides .env
  };

  bcryptTest(options);
}

hashSync("abcdef", Number(process.env.BCRYPT_SALT)); // Env. vars are strings and will upset bcrypt
```

# Future

I may add more functionality such as wrapper functions for bcrypt that use the optimal value automatically, or that
check and rehash if the salt value has changed (on user login, for example).
