import os
import sys
import globals


def display_table(table_title, col_names, table_rows):
    from prettytable import PrettyTable
    tmp_table = PrettyTable()

    tmp_table.title = table_title
    tmp_table.field_names = col_names
    for column_name in col_names:
          tmp_table.align[column_name] = "l"

    for row in table_rows:
        tmp_table.add_row(row)

    sys.stdout.write("{}\n".format(table_title))
    sys.stdout.write("{}\n".format(tmp_table))


