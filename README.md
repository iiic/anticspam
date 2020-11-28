  Anticspam
=============

**Antispam hashing library Anticspam**

Use
---

Paste the script file anywhere in the page, like any regular `javascript` module. Settings are in json identified by id `anticspam-settings`

``` html
	<script type="text/json" id="anticspam-settings">
		{
			"publicKey": "8bUxgDitsLvXaBdvq2em",
			"apiEndpoints": [ "https://domain.tls/api/endpoint/" ]
		}
	</script>
<script type="module" src="/anticspam.mjs" crossorigin="anonymous" integrity="sha256-eX4Yr7bQ38SW3yw8IoeRAvu5rr1Kd2wP4pRoe/45NRE="></script>
```

### a simple example of usage is in the `example-usage.html` file ###

# Possible problems?
The mjs extension must have the correct mime type set to `text/javascript`, if it is too laborious, rename the suffix from `.mjs` to `.js`.

# Licence

**CC BY-SA 4.0**

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License. To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/4.0/ or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

-------

More info at https://iiic.dev/anticspam
