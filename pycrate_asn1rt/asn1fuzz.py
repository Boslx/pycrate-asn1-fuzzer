import random
import string
import json
import xml.etree.cElementTree as et


class Asn1Container:
    """
    Represents an ASN.1 data structure with type, optionality, and nesting information.
    This class provides methods for fuzzing ASN.1 data.
    """
    def __init__(self, unique_ident: str, asn1_type: str, optional: bool, nested=None, range=None,
                 sequence_member_count=1):
        """
        Args:
            unique_ident: A unique identifier for the container.
            asn1_type: The ASN.1 type of the container (e.g., "INTEGER", "SEQUENCE", "CHOICE").
            optional: Indicates whether the container is optional within its parent structure.
            nested: Nested Asn1Container objects or values for constructed types.
            range: A tuple representing the range of allowed values (for types like INTEGER).
            sequence_member_count: The number of members in a SEQUENCE OF.
        """
        self.unique_ident = unique_ident
        self.asn1_type = asn1_type
        self.optional = optional
        self.nested = nested
        self.range = range
        self.sequence_member_count = sequence_member_count
        self.fully_covered = False

    def toJson(self):
        """
        Converts the Asn1Container object to a JSON string.

        Returns:
            str: A JSON representation of the object.
        """
        return json.dumps(self, default=lambda o: o.__dict__)

    def reset_coverage(self):
        """
        Resets the coverage flag for the container and its nested elements.
        """
        self.fully_covered = False
        # TODO: Nested reset

    def generate_random_ascii_string(length):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

    def generate_random_number(length):
        return ''.join(str(random.randrange(0, 9)) for _ in range(length))

    def better_randrange(self, start, stop, step=1):
        if start == stop:
            return start
        else:
            return random.randrange(start, stop, step)

    def fuzz(self, allowlist: set = None, blocklist: set = None, coverage_aware: bool = False,
             max_seq_of_count: int = 1):
        """
        Generates fuzzed data for the ASN.1 container based on its type and constraints.

        Args:
            allowlist: A set of identifiers to include in fuzzing.
            blocklist: A set of identifiers to exclude from fuzzing.
            coverage_aware: If True, prioritizes fuzzing uncovered parts of the structure.
            max_seq_of_count: The maximum number of elements to generate for "SEQUENCE OF" types.

        Returns:
            Any: The fuzzed data, which can be a single value or a nested structure.
        """
        return_val = None

        match self.asn1_type:
            case "INTEGER":
                if self.range == None:
                    return_val = random.randrange(0, 128)
                elif self.range[1] == None:
                    return_val = random.randrange(self.range[0], 128)
                elif self.range[0] == self.range[1]:
                    return_val = self.range[0]
                else:
                    return_val = random.randrange(self.range[0], self.range[1])
            case "ENUMERATED":
                return_val = random.choice(self.nested)
            case "BOOLEAN":
                return_val = random.choice([True, False])
            case "OCTET STRING":
                if (self.range == None):
                    return_val = random.randbytes(random.randrange(0, 128))
                elif (self.range[1] == None):
                    return_val = random.randbytes(self.better_randrange(self.range[0], 128))
                else:
                    return_val = random.randbytes(self.better_randrange(self.range[0], self.range[1]))
            case "BIT STRING":
                if (self.nested != None and self.range != None):
                    value = self.better_randrange(0, 2 ** len(self.nested) - 1)
                    return_val = (value, self.range[1])
                    # return_val = (value, self.range[2])
                    # return (random.randrange(self.range[0], self.range[1]), self.range[2])
                elif self.range != None:
                    return_val = (self.better_randrange(self.range[0], self.range[1]), self.range[2])
                elif self.nested != None:
                    value = self.better_randrange(0, 2 ** len(self.nested) - 1)
                    return_val = (value, 8)

            case "IA5String" | "UTF8String":
                if (self.range == None):
                    return_val = Asn1Container.generate_random_ascii_string(128)
                elif (self.range[0] == self.range[1]):
                    return_val = Asn1Container.generate_random_ascii_string(self.range[0])
                else:
                    return_val = Asn1Container.generate_random_ascii_string(
                        random.randrange(self.range[0], self.range[1]))
            case "NumericString":
                if (self.range == None):
                    return_val = Asn1Container.generate_random_number(random.randrange(0, 256))
                else:
                    return_val = Asn1Container.generate_random_number(
                        self.better_randrange(self.range[0], self.range[1]))
            case "NULL":
                return_val = 0
            case "EXPANDABLE":
                raise ValueError("Please remove EXPANDABLEs bevore fuzzing!")
            case "SEQUENCE":
                retNested = {}
                for key, value in self.nested.items():
                    if allowlist != None:
                        if value.unique_ident not in allowlist:
                            continue
                    elif (value.optional and random.choice([True, False]) and (
                            not coverage_aware or self.fully_covered)):
                        continue

                    fuzzed_value = value.fuzz(allowlist, blocklist, coverage_aware, max_seq_of_count)
                    if fuzzed_value is not None:
                        retNested[key] = fuzzed_value
                return_val = retNested
            case "CHOICE" | "OPEN_TYPE" | "ANY":
                nested_filtered = self.nested
                if (coverage_aware):
                    filtered = dict(filter(lambda x: not x[1].fully_covered, nested_filtered.items()))
                    if (len(filtered) > 0):
                        nested_filtered = filtered
                if allowlist != None:
                    for key, value in self.nested.items():
                        if value.unique_ident in allowlist:
                            return_val = (key, value.fuzz(allowlist, blocklist, coverage_aware, max_seq_of_count))
                            break
                else:
                    possible_choices = list(nested_filtered.keys())
                    if (len(possible_choices) > 1):
                        selectedKey = random.choice(possible_choices)
                    else:
                        selectedKey = possible_choices[0]
                    return_val = (
                        selectedKey,
                        self.nested[selectedKey].fuzz(allowlist, blocklist, coverage_aware, max_seq_of_count))
            case "SEQUENCE OF":
                ret = []
                if self.range == None:
                    numElementsSequence = random.randrange(1, max_seq_of_count) if max_seq_of_count != 1 else 1
                elif self.range[1] == None:
                    # Force at least one
                    if not self.fully_covered and self.range[0] == 0:
                        self.range = (1, self.range[1], self.range[2])

                    maxValue = max(self.range[0], max_seq_of_count)
                    numElementsSequence = random.randrange(self.range[0], maxValue) if self.range[
                                                                                           0] != maxValue else maxValue
                else:
                    steps = self.range[2] if self.range[2] is not None else 1
                    max_capped = max(self.range[0] + steps, max_seq_of_count)
                    min_value = self.range[0]
                    if self.range[0] == 0 and not self.fully_covered:
                        min_value = max_capped
                    numElementsSequence = self.better_randrange(min_value, min(self.range[1], max_capped), steps)

                for _ in range(numElementsSequence):
                    ret.append(self.nested.fuzz(allowlist, blocklist, coverage_aware, max_seq_of_count))

                return_val = ret
            case _:
                print(self.asn1_type)

        match self.asn1_type:
            case "SEQUENCE OF":
                self.fully_covered = self.nested.fully_covered
            case "CHOICE" | "OPEN_TYPE" | "ANY" | "SEQUENCE":
                self.fully_covered = True
                for key, value in self.nested.items():
                    if value.fully_covered == False:
                        self.fully_covered = False
            case _:
                self.fully_covered = True

        return return_val

    def expand_once(self, ident_history: dict):
        """
        Expands "EXPANDABLE" nodes in the container once.

        This method replaces "EXPANDABLE" nodes with their nested content,
        effectively expanding the ASN.1 structure one level down.

        Args:
            ident_history (dict): A dictionary to keep track of used identifiers during expansion.
        """
        match self.asn1_type:
            case "CHOICE" | "OPEN_TYPE" | "ANY" | "SEQUENCE":
                for key, value in self.nested.items():
                    if value.asn1_type == "EXPANDABLE" and value.nested is not None:
                        self.nested[key] = value.nested.get_proto(ident_history=ident_history)
                    else:
                        value.expand_once(ident_history)

    def coverage(self) -> list:
        """
        Calculates the element coverage of the ASN.1 container.

        Returns:
            list: A list containing two integers:
                  - The first integer represents the total number of elements in the container.
                  - The second integer represents the number of elements that have been covered.
        """
        result_val = [0, 0]
        match self.asn1_type:
            case "CHOICE" | "OPEN_TYPE" | "ANY" | "SEQUENCE":
                for key, value in self.nested.items():
                    if not isinstance(value, Asn1Container):
                        continue

                    coverage_val = value.coverage()
                    result_val[0] += coverage_val[0]
                    result_val[1] += coverage_val[1]
            case "SEQUENCE OF":
                return self.nested.coverage()
            case _:
                result_val = (1, int(self.fully_covered))

        return result_val

    def remove_expandable(self) -> bool:
        """
        Removes "EXPANDABLE" nodes from the container.

        This method attempts to remove "EXPANDABLE" nodes by removing optional elements or choices.

        Returns:
            bool: True if all "EXPANDABLE" nodes were successfully removed, False otherwise.
        """
        result: bool = True

        # Create a list to store keys to be removed
        keys_to_remove = []

        match self.asn1_type:
            case "EXPANDABLE":
                # The enemy
                result = False
            case "CHOICE" | "OPEN_TYPE" | "ANY":
                # case "CHOICE" | "ANY":
                for key, value in self.nested.items():
                    is_removed = value.remove_expandable()
                    if not is_removed:
                        keys_to_remove.append(key)
            case "SEQUENCE":
                for key, value in self.nested.items():
                    is_removed = value.remove_expandable()
                    if is_removed:
                        continue

                    # Remove optional elements
                    if value.optional:
                        keys_to_remove.append(key)
                        continue

                    # We may have lost the battle, but not the war
                    result = False
            case "SEQUENCE OF":
                if self.nested is None:
                    # Dirty hack for IVIM
                    return False
                return self.nested.remove_expandable()

        # Remove the keys from the dictionary
        for key in keys_to_remove:
            del self.nested[key]

        return result

    def mandatory(self) -> str:
        """
        (Helper for XML) Returns a string representation of the optionality of the container.

        Returns:
            str: "true" if the container is mandatory, "false" if optional.
        """
        return "true" if not self.optional else "false"

    def feature_ide(self, root, name_dict):
        """
        Generates an XML representation of the container for FeatureIDE.

        This method creates an XML structure that represents the ASN.1 container and its components,
        suitable for import into FeatureIDE

        See: https://featureide.github.io/

        Args:
            root: The root XML element to which the container's representation will be added.
            name_dict: A dictionary to keep track of used names.
        """
        match self.asn1_type:
            # case "CHOICE" | "OPEN_TYPE" | "ANY":
            case "CHOICE" | "ANY":
                newRoot = et.SubElement(root, "alt", mandatory=self.mandatory(), name=self.unique_ident)
                for _, value in self.nested.items():
                    value.feature_ide(newRoot, name_dict)
            case "SEQUENCE":
                newRoot = et.SubElement(root, "and", mandatory=self.mandatory(), name=self.unique_ident)
                for _, value in self.nested.items():
                    value.feature_ide(newRoot, name_dict)
            case "SEQUENCE OF":
                newRoot = et.SubElement(root, "and", mandatory=self.mandatory(), name=f"seq_{self.unique_ident}")
                self.nested.feature_ide(newRoot, name_dict)
            case _:
                et.SubElement(root, "feature", mandatory=self.mandatory(), name=self.unique_ident)
