import csv

# Define column indices
C = {
    'scantimes': 0,
    'id': 1,
    'addr': 2,
    'start': 3,
    'end': 4,
    'index': 5,
    'pteprot': 6,
    'vmflags': 7,
    'accessed': 8
}

# for output files
COLS = {
    'scantimes': 0,
    'id': 1,
    'offset': 2,
    'codeid': 3,
    'codebitmap':4,
    'pteprot': 5,
    'vmflags': 6,
    'accessed': 7
}

VM_READ	 = 0x00000001
VM_WRITE = 0x00000002
VM_EXEC	 = 0x00000004
VM_SHARED = 0x00000008

class CSVParser:
    def __init__(self, input_filename, output_filename):
        self.input_filename = input_filename
        self.output_filename = output_filename
        self.prev = None
        self.output_table = []
        self.scantimes = 0
        self.codeid = ''
        self.codebitmap = ''

    # def compare_rows(self, current_row):
    #     # Implement your comparison logic here
    #     # Example: Compare 'id' of current and previous row
    #     if self.previous_row and curr[C['id']] != self.previous_row[COLUMNS['id']]:
    #         # Perform your logic to generate a new row
    #         # Example: return current_row with a modification
    #         new_row = current_row[:]
    #         new_row[COLUMNS['accessed']] = 'Updated'  # Example modification
    #         return new_row
    #     return None
    
    def fill_gaps(self, scantimes, id, offstart, offend, pteprot, vmflags):
        for i in range(offstart, offend, 1):
            tmpl = ''.join(str(element) for element in self.codebitmap)
            x = [scantimes, id, i, self.codeid, tmpl, pteprot, vmflags, 0]
            self.output_table.append(x)
        return None
             
            


    def addcurr(self, curr):
        tmpl = ''.join(str(element) for element in self.codebitmap)
        x = [self.scantimes, curr[C['id']], curr[C['index']], self.codeid, tmpl, curr[C['pteprot']], curr[C['vmflags']], curr[C['accessed']] ]
        self.output_table.append(x)
        return None

    
    def dispatch_rows(self, curr):
        vmflags = int(curr[C['vmflags']], 16)
        if self.prev == None:

            if vmflags & VM_EXEC != 0:

                self.codeid = curr[C['id']]
                s = int(curr[C['start']], 16)
                e = int(curr[C['end']], 16)
                l = int((e-s) / 4096)

                self.codebitmap = [0] * l
                if curr[C['accessed']] == '1':
                    self.codebitmap[int(curr[C['index']])] = 1
            else:
                # 判断起始index
                idx = curr[C['index']]
                if idx != 0:
                    self.fill_gaps(curr[C['scantimes']],curr[C['id']], 0, curr[C['index']], curr[C['pteprot']], curr[C['vmflags']])
                self.addcurr(curr)
        else:
            if self.scantimes != int(curr[C['scantimes']]):
                self.scantimes = int(curr[C['scantimes']])
                if vmflags & VM_EXEC != 0:
                    self.codeid = curr[C['id']]
                    s = int(curr[C['start']], 16)
                    e = int(curr[C['end']], 16)
                    l = int((e-s) / 4096)
                    
                    self.codebitmap = [0] * l
                    if curr[C['accessed']] == '1':
                        self.codebitmap[int(curr[C['index']])] = 1
                else:
                    # 判断起始index
                    idx = curr[C['index']]
                    if idx != 0:
                        self.fill_gaps(curr[C['scantimes']],curr[C['id']], 0, curr[C['index']], curr[C['pteprot']], curr[C['vmflags']])
                    self.addcurr(curr)
            else:
                # 判断是否连续，是否id不同
                if curr[C['id']] != self.prev[C['id']]:
                    if vmflags & VM_EXEC != 0:
                        if curr[C['accessed']] == '1':
                            self.codebitmap[int(curr[C['index']])] = 1
                    else:
                        # 判断结束index
                        s = int(curr[C['start']], 16)
                        e = int(curr[C['end']], 16)
                        l = int((e-s) / 4096)
                        idx0 = int(self.prev[C['index']])
                        if idx0 != l:
                            self.fill_gaps(curr[C['scantimes']],self.prev[C['id']], idx0, l, curr[C['pteprot']], curr[C['vmflags']])

                        # 判断起始index
                        idx = int(curr[C['index']])
                        if idx != 0:
                            self.fill_gaps(curr[C['scantimes']], curr[C['id']], 0, idx, curr[C['pteprot']], curr[C['vmflags']])
                        self.addcurr(curr)
                else:
                    idx0 = int(curr[C['index']])
                    idx1 = int(self.prev[C['index']])
                    if vmflags & VM_EXEC != 0:
                        if curr[C['accessed']] == '1':
                            self.codebitmap[int(curr[C['index']])] = 1
                    else:
                        
                        if idx0-idx1 == 1: # 连续
                            self.addcurr(curr)
                        else: # 不连续
                            self.fill_gaps(curr[C['scantime']], curr[C['id']], idx1, idx0, curr[C['pteprot']], curr[C['vmflags']])
                            self.addcurr(curr)
        self.prev = curr


             

    def process_file(self):
        with open(self.input_filename, mode='r') as infile, \
             open(self.output_filename, mode='w', newline='') as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            c = 0
            for current_row in reader:

                c = c + 1
                self.dispatch_rows(current_row)
                # if c == 1000:
                #     break
                    # new_row = self.compare_rows(current_row)
                # if new_row:
                #     writer.writerow(new_row)
                # self.previous_row = current_row
            
            for tab in self.output_table:
                writer.writerow(tab)

if __name__ == "__main__":
    infile = 'sample-30sec-2023-12-12-22-48.csv'
    outfile = '30sec-2023-12-12-22-48.csv'
    parser = CSVParser(infile, outfile)
    parser.process_file()

