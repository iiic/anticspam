export class append
{
	constructor ( /** @type {Object} */ o = Object )
	{
		const FUNCTION_NAME = 'deepAssign';

		if ( typeof o()[ FUNCTION_NAME ] !== 'function' ) {
			o.defineProperty( o.prototype, FUNCTION_NAME, {
				value: function ( /** @type {Array} */ ...args )
				{
					let currentLevel = o;
					args.forEach( ( /** @type {Object} */ source ) =>
					{
						if ( source instanceof Array ) {
							currentLevel = source;
						} else {
							o.entries( source ).forEach( ( [ /** @type {String} */ key, value ] ) =>
							{
								if ( value instanceof o && key in currentLevel ) {
									value = o[ FUNCTION_NAME ]( currentLevel[ key ], value );
								}
								currentLevel = { ...currentLevel, [ key ]: value };
							} );
						}
					} );
					return currentLevel;
				},
				writable: false,
				configurable: false,
				enumerable: false,
			} );
		}
	}
}
