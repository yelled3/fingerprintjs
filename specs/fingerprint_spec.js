describe("Fingerprint", function(){
  beforeEach(function() {
    this.addMatchers({
      toBeInstanceOf : function(expected) {
        return this.actual instanceof expected && this.actual.length > 0;
      },
      toBeA: function(expected) {
        return typeof this.actual === expected;
      }
    });
  });
  describe("new Fingerprint", function(){
    it("Creates a new instance of Fingerprint", function(){
      expect(new Fingerprint).not.toBe(null);
    });

    it("Accepts a custom hashing function as argument", function(){
      var hasher = function(input, seed){return 31;}
      expect(new Fingerprint(hasher)).not.toBe(null);
    });
  });

  describe("#get", function(){
    it("Calculates browser fingerprint with built-in hashing if no custom hashing is given", function(){
      var fingerprint = new Fingerprint;
      spyOn(fingerprint, 'murmurhash3_32_gc');      
      fingerprint.get();
      expect(fingerprint.murmurhash3_32_gc).toHaveBeenCalled();
    });

    it("Calculates browser fingerprint with custom hashing if it is given", function(){
      var hasher = function(value, seed){return 'abcdef'}
      var fingerprint = new Fingerprint(hasher);
      expect(fingerprint.get()).toEqual('abcdef');
    });


    it("Returns a number as a fingerprint value when used with a built-in hashing function", function(){
      var fingerprint = new Fingerprint;
      expect(fingerprint.get()).toBeA('number');
    })
  });
});