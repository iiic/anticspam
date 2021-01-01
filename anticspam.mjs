/**
* @private
* @module Anticspam
* @classdesc Private part of antispam library Anticspam.
* @author ic < ic.czech@gmail.com >
* @see https://iiic.dev/anticspam
* @license https://creativecommons.org/licenses/by-sa/4.0/legalcode.cs CC BY-SA 4.0
* @since Q4 2020
* @version 0.4
* @readonly
*/
const AnticspamPrivate = class
{

	static INPUT_NODE_NAME = 'INPUT';
	static TEXTAREA_NODE_NAME = 'TEXTAREA';
	static INPUT_TYPE_HIDDEN = 'hidden';
	static SUBMIT_EVENT = 'submit';
	static CONTENT_TYPE = 'application/json; charset=utf-8';
	static DATA_TYPES = {
		URL: 'urls',
		EMAIL: 'emails',
		TEXT: 'texts',
		HUNDREDTH: 'hundredths'
	};
	static INPUT_TYPE = {
		URL: 'url',
		EMAIL: 'email'
	};


	/**
	 * @public
	 * @type {Object}
	 * @description default settings… can be overwritten
	 */
	settings = {
		description: 'This text is used as a salt for hash (sha-256). Keep this text unchanged. For more information about this anti spam library visit https://github.com/iiic/anticspam or https://iiic.dev/anticspam',
		watchedFieldsQSA: {
			urls: [ '[type="url"]' ],
			emails: [ '[type="email"]' ],
			texts: [ 'textarea[required][name="comment"]', '[type="text"].content' ],
		},
		publicKey: null, // public key for API access
		apiEndpoints: [], // array one or many urls
		splitLimit: 100,
		antispamFormsQSA: '.comment-form',
		antispamFormFieldName: 'antispam-field-api-result',
		antispamFormFieldNameSignature: 'antispam-field-api-signature',
		modulesImportPath: 'https://iiic.dev/js/modules',
		autoRun: true,
	};

	/**
	* @public
	* @type {NodeListOf<HTMLFormElement>}
	*/
	formElements;

	/**
	* @public
	* @type {Function}
	*/
	formSubmitFunction;


	async initImportWithIntegrity ( /** @type {Object} */ settings = null )
	{

		console.groupCollapsed( '%cAnticspamPrivate %c initImportWithIntegrity %c(' + ( settings === null ? 'without settings' : 'with settings' ) + ')',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME,
			Anticspam.CONSOLE.INTEREST_PARAMETER
		);
		console.debug( { arguments } );
		console.groupEnd();

		return new Promise( ( /** @type { Function } */ resolve ) =>
		{
			const ip = settings && settings.modulesImportPath ? settings.modulesImportPath : this.settings.modulesImportPath;
			import( ip + '/importWithIntegrity.mjs' ).then( ( /** @type {Module} */ module ) =>
			{
				/** @type {Function} */
				this.importWithIntegrity = module.importWithIntegrity;
				resolve( true );
			} ).catch( () =>
			{
				const SKIP_SECURITY_URL = '#skip-security-test-only'
				if ( window.location.hash === SKIP_SECURITY_URL ) {
					console.warn( '%cAnticspamPrivate %c initImportWithIntegrity %c without security!',
						Anticspam.CONSOLE.CLASS_NAME,
						Anticspam.CONSOLE.METHOD_NAME,
						Anticspam.CONSOLE.WARNING
					);
					this.importWithIntegrity = (/** @type {String} */ path ) =>
					{
						return new Promise( ( /** @type {Function} */ resolve ) =>
						{
							import( path ).then( ( /** @type {Module} */ module ) =>
							{
								resolve( module );
							} );
						} );
					};
					resolve( true );
				} else {
					throw 'Security Error : Import with integrity module is missing! You can try to skip this error by adding ' + SKIP_SECURITY_URL + ' hash into website URL';
				}
			} );
		} );
	}

	initFormSubmitFunction ()
	{
		console.debug( '%cAnticspamPrivate %c initFormSubmitFunction',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		this.formSubmitFunction = this.getAntispamResponse.bind( this );
	}

	getValuesFrom ( /** @type {HTMLFormElement} */ form )
	{
		console.debug( '%cAnticspamPrivate %c getValuesFrom',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME,
			{ arguments }
		);

		const dataToSend = {
			[ AnticspamPrivate.DATA_TYPES.URL ]: new Set(),
			[ AnticspamPrivate.DATA_TYPES.EMAIL ]: new Set(),
			[ AnticspamPrivate.DATA_TYPES.TEXT ]: new Set(),
			[ AnticspamPrivate.DATA_TYPES.HUNDREDTH ]: new Set()
		};

		[
			AnticspamPrivate.DATA_TYPES.URL,
			AnticspamPrivate.DATA_TYPES.EMAIL,
			AnticspamPrivate.DATA_TYPES.TEXT
		].forEach( ( /** @type {String} */ group ) =>
		{
			this.settings.watchedFieldsQSA[ group ].forEach( ( /** @type {String} */ qsa ) =>
			{
				form.querySelectorAll( qsa ).forEach( ( /** @type {HTMLInputElement} */ input ) =>
				{
					if ( input.value ) {
						dataToSend[ group ].add( input.value );
						const charsLength = input.value.length;
						if ( group === AnticspamPrivate.DATA_TYPES.TEXT && charsLength > this.settings.splitLimit ) {
							for ( let i = 0; i < charsLength; i += this.settings.splitLimit ) {
								dataToSend[ AnticspamPrivate.DATA_TYPES.HUNDREDTH ].add( input.value.substring( i, i + this.settings.splitLimit ) );
							}
						}
					}
				} );
			} );
		} );

		const keys = Object.keys( dataToSend );
		keys.forEach( ( /** @type {String} */ key ) =>
		{
			dataToSend[ key ] = [ ...dataToSend[ key ] ]; // Set to Array
		} );

		return dataToSend;
	}

	async prepareHashes ( /** @type {Object} */ dataToSend )
	{
		console.debug( '%cAnticspamPrivate %c prepareHashes',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME,
			{ arguments }
		);

		const innerPromises = [];
		const groups = [
			AnticspamPrivate.DATA_TYPES.URL,
			AnticspamPrivate.DATA_TYPES.EMAIL,
			AnticspamPrivate.DATA_TYPES.TEXT,
			AnticspamPrivate.DATA_TYPES.HUNDREDTH
		];
		for ( const group of groups ) {
			for ( const key in dataToSend[ group ] ) {
				dataToSend[ group ][ key ] = Anticspam.sha256( this.settings.description + dataToSend[ group ][ key ] );
			}
			innerPromises.push( Promise.all( dataToSend[ group ] ) );
		}

		return Promise.all( innerPromises ).then( ( /** @type {Array} */ results ) =>
		{
			const keys = Object.keys( dataToSend );
			let i = 0;
			keys.forEach( ( /** @type {String} */ key ) =>
			{
				dataToSend[ key ] = results[ i ];
				i++;
			} );
			return JSON.stringify( dataToSend );
		} );
	}

	async prepareFetches ( hashedDataToSend )
	{
		console.debug( '%cAnticspamPrivate %c prepareFetches',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		const promises = [];
		this.settings.apiEndpoints.forEach( ( /** @type {String} */ endpoint ) =>
		{
			promises.push(
				fetch( endpoint, {
					method: 'POST',
					headers: new Headers( {
						'content-type': AnticspamPrivate.CONTENT_TYPE,
						'x-public-key': this.settings.publicKey
					} ),
					body: hashedDataToSend,
					cache: 'no-cache',
					referrer: 'no-referrer',
					mode: 'cors',
				} ).then( ( /** @type {Response} */ response ) =>
				{
					return response.json();
				} )
			);
		} );
		return promises;
	}

	submit ( /** @type {HTMLFormElement} */ form )
	{
		console.debug( '%cAnticspamPrivate %c submit',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		if ( typeof form.submit === 'function' ) {
			form.submit();
		} else {
			form.submit.click();
		}
	}

	async getAntispamResponse ( /** @type {SubmitEvent} */ event )
	{
		console.debug( '%cAnticspamPrivate %c getAntispamResponse',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		event.preventDefault();
		event.stopPropagation();

		/** @type {HTMLFormElement} */
		const form = event.target;

		const textFormDataToSend = this.getValuesFrom( form );
		const hashedDataToSend = await this.prepareHashes( textFormDataToSend );
		const promises = await this.prepareFetches( hashedDataToSend );

		Promise.any( promises ).then( ( /** @type {Object} */ first ) =>
		{

			/** @type {HTMLInputElement} */
			const inputResult = form.querySelector( AnticspamPrivate.INPUT_NODE_NAME + '[name=' + this.settings.antispamFormFieldName + ']' );

			if ( inputResult ) {
				inputResult.value = first.result;
			}

			/** @type {HTMLInputElement} */
			const inputSignature = form.querySelector( AnticspamPrivate.INPUT_NODE_NAME + '[name=' + this.settings.antispamFormFieldNameSignature + ']' );

			if ( inputSignature ) {
				inputSignature.value = first.signature;
			}
			if ( form.checkValidity() ) {
				form.removeEventListener(
					AnticspamPrivate.SUBMIT_EVENT,
					this.formSubmitFunction,
					{ once: false, capture: false }
				);
				this.submit( form );
			}
		} );
	}
} // AnticspamPrivate

/**
* @public
* @module Anticspam
* @classdesc Antispam hashing library Anticspam.
* @author ic < ic.czech@gmail.com >
* @see https://iiic.dev/anticspam
* @license https://creativecommons.org/licenses/by-sa/4.0/legalcode.cs CC BY-SA 4.0
* @since Q4 2020
* @version 0.4
*/
export class Anticspam
{

	static CONSOLE = {
		CLASS_NAME: 'color: gray',
		METHOD_NAME: 'font-weight: normal; color: green',
		INTEREST_PARAMETER: 'font-weight: normal; font-size: x-small; color: blue',
		EVENT_TEXT: 'color: orange',
		WARNING: 'color: red',
	};

	/**
	 * @private
	 * @description '#private' is not currently supported by Firefox, so that's why '_private'
	 */
	_private;


	constructor (
		/** @type {HTMLScriptElement | null} */ settingsElement = null
	)
	{
		console.groupCollapsed( '%c Anticspam',
			Anticspam.CONSOLE.CLASS_NAME
		);
		console.debug( '%c' + 'constructor',
			Anticspam.CONSOLE.METHOD_NAME,
			[ { arguments } ]
		);

		this._private = new AnticspamPrivate;

		/** @type {Object} */
		const settings = JSON.parse( settingsElement.text );

		this._private.initImportWithIntegrity( settings ).then( () =>
		{
			if ( settings ) {
				this.setSettings( settings ).then( () =>
				{
					if ( this.settings.autoRun ) {
						this.run();
					}
				} );
			} else if ( this.settings.autoRun ) {
				this.run();
			}
		} );
		console.groupEnd();
	}


	/**
	 * @description : get script settings
	 * @returns {Object} settings of self
	 */
	get settings ()
	{
		return this._private.settings;
	}

	set settings ( /** @type {Object} */ inObject )
	{
		Object.assign( this._private.settings, inObject );
	}

	/**
	 * @description : Get dynamic Import function
	 * @returns {Function}
	 */
	get importWithIntegrity ()
	{
		return this._private.importWithIntegrity;
	}

	set formElements ( /** @type {NodeListOf<HTMLFormElement>} */ formElements )
	{
		this._private.formElements = formElements;
	}

	/**
	 * @returns {NodeListOf<HTMLFormElement>}
	 */
	get formElements ()
	{
		return this._private.formElements;
	}

	/**
	 * @returns {Function}
	 */
	get formSubmitFunction ()
	{
		return this._private.formSubmitFunction;
	}

	async setSettings ( /** @type {Object} */ inObject )
	{
		console.groupCollapsed( '%cAnticspam %c setSettings',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);
		console.debug( { arguments } );
		console.groupEnd();

		return new Promise( ( /** @type {Function} */ resolve ) =>
		{
			if ( inObject.modulesImportPath ) {
				this.settings.modulesImportPath = inObject.modulesImportPath;
			}
			this.importWithIntegrity(
				this.settings.modulesImportPath + '/object/deepAssign.mjs',
				'sha256-qv6PwXwb5wOy4BdBQVGgGUXAdHKXMtY7HELWvcvag34='
			).then( ( /** @type {Module} */ deepAssign ) =>
			{
				new deepAssign.append( Object );
				this._private.settings = Object.deepAssign( this.settings, inObject ); // multi level assign
				resolve( true );
			} ).catch( () =>
			{
				Object.assign( this._private.settings, inObject ); // single level assign
				resolve( true );
			} );
		} );
	}

	static async sha256 ( /** @type {String} */ message )
	{
		console.debug( '%cAnticspam %c sha256 %c(' + message + ')',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME,
			Anticspam.CONSOLE.INTEREST_PARAMETER
		);

		const msgUint8 = new TextEncoder().encode( message ); // encode as UTF-8
		const hashBuffer = await crypto.subtle.digest( 'SHA-256', msgUint8 ); // hash the message
		const hashArray = Array.from( new Uint8Array( hashBuffer ) ); // convert ArrayBuffer to Array
		return hashArray.map( b => ( '00' + b.toString( 16 ) ).slice( -2 ) ).join( '' ); // convert bytes to hex string
	}

	appendHiddenFieldForAntispamBy ( /** @type {HTMLFormElement} */ form )
	{

		/** @type {HTMLInputElement} */
		const inputResult = ( document.createElement( AnticspamPrivate.INPUT_NODE_NAME ) );

		inputResult.type = AnticspamPrivate.INPUT_TYPE_HIDDEN;
		inputResult.name = this.settings.antispamFormFieldName;
		inputResult.required = true;

		/** @type {HTMLInputElement} */
		const inputSignature = ( document.createElement( AnticspamPrivate.INPUT_NODE_NAME ) );
		inputSignature.type = AnticspamPrivate.INPUT_TYPE_HIDDEN;
		inputSignature.name = this.settings.antispamFormFieldNameSignature;
		inputSignature.required = true;

		form.appendChild( inputResult );
		form.appendChild( inputSignature );
	}

	appendAntispamOnForms ()
	{
		console.debug( '%cAnticspam %c appendAntispamOnForm',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		if ( this.settings.antispamFormsQSA && !this.formElements ) {
			this.formElements = document.body.querySelectorAll( this.settings.antispamFormsQSA );
		}
		if ( this.formElements ) {
			[ ...this.formElements ].forEach( ( /** @type {HTMLFormElement} */ form ) =>
			{
				this.appendHiddenFieldForAntispamBy( form );
				form.addEventListener(
					AnticspamPrivate.SUBMIT_EVENT,
					this.formSubmitFunction,
					{ once: false, capture: false }
				);
			} );
		}
	}

	/**
	 * @description: check if important fields of antispam are selectable by querySelector strings set by settings, also try to repair if possible
	 */
	checkAntispamImportantFields ()
	{
		console.debug( '%cAnticspam %c checkAntispamImportantFields',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		if ( this.settings.antispamFormsQSA && !this.formElements ) {
			this.formElements = document.body.querySelectorAll( this.settings.antispamFormsQSA );
		}
		const workingElements = [];
		if ( this.formElements ) {
			this.formElements.forEach( ( /** @type {HTMLFormElement} */ form ) =>
			{
				workingElements.push( form );
			} );
		}
		workingElements.forEach( ( /** @type {HTMLElement} */ element ) =>
		{
			const urls = this.settings.watchedFieldsQSA.urls;
			const emails = this.settings.watchedFieldsQSA.emails;
			const texts = this.settings.watchedFieldsQSA.texts;
			urls.forEach( ( /** @type {String} */ qsa ) =>
			{
				let valid = false;
				element.querySelectorAll( qsa ).forEach( ( /** @type {HTMLInputElement} */ input ) =>
				{
					if ( input && input.nodeType === Node.ELEMENT_NODE && ( input.nodeName === AnticspamPrivate.INPUT_NODE_NAME || input.nodeName === AnticspamPrivate.TEXTAREA_NODE_NAME ) ) {
						if ( input.type === AnticspamPrivate.INPUT_TYPE.URL ) {
							valid = true;
						} else if ( input.type === AnticspamPrivate.INPUT_TYPE.EMAIL ) {
							this.settings.watchedFieldsQSA.emails.push( qsa );
						} else {
							this.settings.watchedFieldsQSA.texts.push( qsa );
						}
					}
				} );
				if ( !valid ) {
					const index = urls.indexOf( qsa );
					if ( index !== -1 ) {
						urls.splice( index, 1 );
					}
				}
			} );
			emails.forEach( ( /** @type {String} */ qsa ) =>
			{
				let valid = false;
				element.querySelectorAll( qsa ).forEach( ( /** @type {HTMLInputElement} */ input ) =>
				{
					if ( input && input.nodeType === Node.ELEMENT_NODE && ( input.nodeName === AnticspamPrivate.INPUT_NODE_NAME || input.nodeName === AnticspamPrivate.TEXTAREA_NODE_NAME ) ) {
						if ( input.type === AnticspamPrivate.INPUT_TYPE.EMAIL ) {
							valid = true;
						} else if ( input.type === AnticspamPrivate.INPUT_TYPE.URL ) {
							this.settings.watchedFieldsQSA.urls.push( qsa );
						} else {
							this.settings.watchedFieldsQSA.texts.push( qsa );
						}
					}
				} );
				if ( !valid ) {
					const index = emails.indexOf( qsa );
					if ( index !== -1 ) {
						emails.splice( index, 1 );
					}
				}
			} );
			texts.forEach( ( /** @type {String} */ qsa ) =>
			{
				let valid = false;
				element.querySelectorAll( qsa ).forEach( ( /** @type {HTMLInputElement} */ input ) =>
				{
					if ( input && input.nodeType === Node.ELEMENT_NODE && ( input.nodeName === AnticspamPrivate.INPUT_NODE_NAME || input.nodeName === AnticspamPrivate.TEXTAREA_NODE_NAME ) ) {
						if ( input.type === AnticspamPrivate.INPUT_TYPE.EMAIL ) {
							this.settings.watchedFieldsQSA.emails.push( qsa );
						} else if ( input.type === AnticspamPrivate.INPUT_TYPE.URL ) {
							this.settings.watchedFieldsQSA.urls.push( qsa );
						} else {
							valid = true;
						}
					}
				} );
				if ( !valid ) {
					const index = texts.indexOf( qsa );
					if ( index !== -1 ) {
						texts.splice( index, 1 );
					}
				}
			} );
		} );
	}

	checkRequirements ()
	{
		console.debug( '%cAnticspam %c checkRequirements',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		if ( !this.settings.description ) {
			throw new Error( 'Description is missing' );
		}
		if ( !this.settings.publicKey ) {
			throw new Error( 'Public key for API was not set' );
		}
		if ( !this.settings.apiEndpoints || !this.settings.apiEndpoints.length || this.settings.apiEndpoints.length <= 0 ) {
			throw new Error( 'One or many API Endpoints are missing' );
		}
		if ( !( 'subtle' in crypto ) ) {
			throw new Error( 'SubtleCrypto library is missing! In Firefox this library is accessible only on secured connection (https)' );
		}
	}

	initFormSubmitFunction ()
	{
		console.debug( '%cAnticspam %c initFormSubmitFunction',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		this._private.initFormSubmitFunction();
	}

	run ()
	{
		console.groupCollapsed( '%cAnticspam %c run',
			Anticspam.CONSOLE.CLASS_NAME,
			Anticspam.CONSOLE.METHOD_NAME
		);

		this.checkRequirements();
		this.checkAntispamImportantFields(); // can be skipped
		this.initFormSubmitFunction();
		this.appendAntispamOnForms();

		console.groupEnd();

		return true;
	}

}

new Anticspam( document.getElementById( 'anticspam-settings' ) );
