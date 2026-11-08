from hashid import HashID

class HashIdentifier:
    def __init__(self,hash_value):
        self.hash_value = hash_value

    def identify(self):
        hashid =HashID()
        hashes=list(hashid.identifyHash(self.hash_value))
        return hashes
        