class HashParser:

    def parse(self, hashes):

        results = []

        for hash_info in hashes:

            result = {
                "hash_type": hash_info.name,
                "hashcat": hash_info.hashcat,
                "john": hash_info.john,
                "extended": hash_info.extended
            }

            results.append(result)

        return results