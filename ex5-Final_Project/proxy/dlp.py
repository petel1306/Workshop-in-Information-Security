# DLP blade for C code detection

declarators = ['char', 'int', 'short', 'float', 'double', 'long', 'auto', 'volatile', 'const', 'unsigned', 'signed',
               'struct', 'enum', 'union', 'extern', 'register', 'inline', 'static']

control_keywords = ['for', 'while', 'do', 'break', 'continue', 'if', 'else', 'switch', 'case', 'goto', 'return']

comments = ['//', '/*', '/**']

# Threshold variables
c_block_size_thresh = 3     # Detect c-blocks of size >= 10
c_lines_min_thresh = 20         # At least 20 c-lines to be considered as c code
c_blocks_amount_thresh = 5  # Expects at least 5 c-blocks in c code
c_lines_amount_thresh = 100 # Expects at least 200 c-lines in c code
c_lines_frac_thresh = 0.25  # Expects at least 30% of c-lines from all the lines

def get_text(path):
    with open(path, 'r') as file:
        return file.read()

def detect_c_code(text):
    # Split the text by: ; { } in order to get c lines
    plain_text = text.replace('\n', '')
    lines = plain_text.replace('{',';').replace('}',';').split(';')
    lines = [line.strip() for line in lines]

    variables = []

    # Find lines that likely to be c lines
    locations = []
    for i, line in enumerate(lines):
        words = line.split()
        if not words or len(words) == 0:
            continue
        starter = words[0]

        # Checks if the line is either conrol, declartion, or assignment

        is_control = starter in control_keywords

        is_declaration = starter in declarators

        is_comment = starter in comments

        # If there is declaration than we find the variable (the word follows the declarators) and remember it
        if is_declaration:
            # Finds the first word that not in declarators
            for word in words:
                if word not in declarators:
                    variables.append(word)

        # Check if line is of the form: var = ...
        var = starter.replace('->', '.').split('.')[0]
        is_assignment = (var[0] in variables) and len(words) > 2 and (words[1] == '=')

        if is_control or is_declaration or is_comment or is_assignment:
            locations.append(i)

    # Find c blocks
    if not locations:
        return None

    blocks = []
    block = locations[0]
    prev = locations[0]
    size = 1
    for loc in locations[1:]:
        if prev + 1 == loc:
            # The streak continues
            size += 1
        else:
            # end of streak
            if (size >= c_block_size_thresh):
                # add the block
                blocks.append(block)

            block = loc
            size = 1

        prev = loc

    # Collect data
    c_blocks_amount = len(blocks)
    c_lines_amount = len(locations)
    c_lines_frac = len(locations) / len(lines)

    # Return answer
    if (c_lines_amount < c_lines_min_thresh):
        return False
    return (c_blocks_amount >= c_blocks_amount_thresh) or (c_lines_amount >= c_lines_amount_thresh)\
           or (c_lines_frac >= c_lines_frac_thresh)
