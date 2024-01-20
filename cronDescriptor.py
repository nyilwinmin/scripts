#for describing cron expressions into text
#put all the cron expressions into a text file 'cron_expressions.txt' in the same directory


from cron_descriptor import get_description
        


# cron_expressions = [
    # "*/5 * * * *",
    # "invalid_cron_expression",
    # "0 1 * * *",
    # "@reboot",
    # "0 2 * * *"
# ]

def get_description_2():
    descriptions = []
    with open("cron_expressions.txt") as f:
        for expression in f:
            try:
                description = get_description(expression)
                descriptions.append(description)
            except Exception as e:
                # error_message = f"Error processing '{expression}': {e}"
                error_message = f"{e}"
                descriptions.append(error_message)
        return descriptions


#print descriptions 
descriptions = get_description_2()
for description in descriptions:
    print(description)