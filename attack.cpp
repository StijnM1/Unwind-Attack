#include "sbt_opt.hpp"
#include "program_options.hpp"
#include <iostream>
#include <vector>  
#include <fstream>
#include <string>
#include <unordered_set>
#include <iomanip>

namespace po = program_options;

state_t original_input; // input lfsr_register value
state_t original_output; // output crypto_buffer

state_t original_key; // for testing purposes the actual true key

state_t key_known_bits_mask; // mask to limit the key search space

std::ofstream myfile("output.txt");

std::map<int, double> weights;

/* 
    Class representating a List
    BPmask is a mask representing the chosen byte paths
    keymask is a mask representing the keybits needed (BPmask implies keymask)
    keylist is a list of all valid keys where relevant bits are specified according to keymask 
*/

class List{
    public:
        state_t BPmask;
        state_t keymask;
        std::vector<state_t> keylist;
};

struct state_hash {
     size_t operator()(state_t x) const { return _h(x.u64); }
     std::hash<uint64_t> _h;
};

double check_probs(std::map<state_t, double> probs) {
    double total = 0;
    for (const auto& val : probs) {
        total += val.second;
    }
    return total;
}

bool mapeqlist(std::map<state_t, double> probs, std::vector<state_t> vec) {
    if (probs.size() != vec.size()) { return false; }
    for (state_t p : vec) {
        if (probs.contains(p)) { continue; }
        else { return false; }
    }
    return true;
}

void printmap(const std::map<state_t, double> map) {
    std::cout << "-----PRINTING MAP-----" << std::endl;
    std::cout << "Map probability: " << check_probs(map) << std::endl;
    for (auto p : map)
    {
        if (p.second < 0) { continue; }
        std::cout << p.first << p.second << ' ' << std::endl;
    }
    std::cout << "------END OF MAP------" << std::endl;
};

std::map<state_t, double> change_keymap(std::map<state_t, double> probs, state_t old_keymap, state_t new_keymap) {
    if (probs.count(new_keymap) == 0){
        probs.insert({ new_keymap, probs[old_keymap]});
        probs.erase(old_keymap);
    }
    else if (new_keymap != old_keymap){
        probs[new_keymap] += probs[old_keymap];
        probs.erase(old_keymap);
    }

    /*for (auto it = probs.begin(); it != probs.end(); )
        if (it->second == 0)
            it = probs.erase(it);
        else
            ++it;*/
    return probs;
};

bool contains(const std::vector<state_t>& vec, state_t state) {
    for (int i = 0; i < vec.size(); ++i) {
        if (vec[i] == state) {
            return true;
        }
    }
    return false;
}

int hammingweight(int64_t vec)
{
    int weight = 0;
    int64_t N = vec;
    while (N)
    {
        weight++;
        N &= N - 1;
    }
    return weight;
}

void printvec(const std::vector<state_t> vec){
    for (state_t i: vec)
        {std::cout << i << ' ';}
    std::cout << std::endl;
    };

void printset(const std::unordered_set<state_t, state_hash> set){
    for (state_t i: set)
        {std::cout << i << ' ';}
    std::cout << std::endl;
    };

bool check_key_mask(const state_t key, const state_t keymask){
    if (((key.u64 ^ original_key.u64) & (key_known_bits_mask.u64 & keymask.u64)) == 0)
        {return true;}
    return false;
    }

void apply_key_mask(List& list){
    for(int i=0; i<list.keylist.size();)
    {
        if (check_key_mask(list.keylist[i], list.keymask))
        {           
            i++;continue;
        }
        std::swap(list.keylist[i], list.keylist.back());
        list.keylist.pop_back();
    }
}

bool valid_mitm(const state_t key, state_t BPmask) {
    state_t original_BPmask = BPmask;
    std::vector<state_t> IList; // list of all possible inputs (per operation)
    std::vector<state_t> OList; // list of all possible outputs (per operation)
    std::unordered_set<state_t, state_hash> OHash;

    // create backwards list first
    state_t initial_output_state = original_output;
    OList.push_back(initial_output_state);

    std::map<state_t, double> probs_fw_in;
    std::map<state_t, double> probs_fw_out;
    std::map<state_t, double> probs_bw_in;
    std::map<state_t, double> probs_bw_out;

    probs_fw_in.clear();
    probs_fw_out.clear();
    probs_bw_in.clear();
    probs_bw_out.clear();

    probs_bw_out[initial_output_state] = 1;


    for (int round = 7; round > 3; --round) {
        std::cout << "Round " << round << std::endl;
        state_t control = SBTopt::control_Nr_Gr(round, key, original_input);
        
        // inverse S boxes
        IList.swap(OList);
        OList.clear();

        probs_bw_in.swap(probs_bw_out);
        probs_bw_out.clear();

        for (state_t input : IList){
            auto input_prob = probs_bw_in[input];
            SBTopt::sbox_inv(input);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output.u64);
            probs_bw_out[output] += input_prob;
        }

        //std::cout << "OList size: " << OList.size() << " probs size: " << probs_bw_out.size() << std::endl;
        std::cout << "same keys? " << mapeqlist(probs_bw_out, OList) << std::endl;


        //printmap(probs_bw_out);
        //printvec(OList);

        // inverse nibble switch
        IList.swap(OList);
        OList.clear();

        probs_bw_in.swap(probs_bw_out);
        probs_bw_out.clear();

        for (state_t input : IList){
            auto input_prob = probs_bw_in[input];
            SBTopt::nibbleswitch_inv(input, control);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output.u64);
            probs_bw_out[output] += input_prob;
        }

        //std::cout << "OList size: " << OList.size() << " probs size: " << probs_bw_out.size() << std::endl;
        std::cout << "same keys? " << mapeqlist(probs_bw_out, OList) << std::endl;

        //printmap(probs_bw_out);
        //printvec(OList);

        SBTopt::bytepermutation_inv(BPmask);

        // inverse byte permutation
        IList.swap(OList);
        OList.clear();

        probs_bw_in.swap(probs_bw_out);
        probs_bw_out.clear();

        //std::cout << IList.size() << std::endl;
        for (state_t input : IList){
            auto input_prob = probs_bw_in[input];
            SBTopt::bytepermutation_inv(input);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output.u64);
            probs_bw_out[output] += input_prob;
        }
        
        if (round == 2 || round == 4 || round == 6)
        {
            // filter unique values every odd round
            OHash.clear();
            OHash.reserve(OList.size());
            for (state_t val : OList)
                OHash.emplace(val);
            OList.clear();
            for (state_t val : OHash)
                OList.emplace_back(val);
        }
        
        //std::cout << "---After byte permutation---" << std::endl;
        //std::cout << "OList size: " << OList.size() << " probs size: " << probs_bw_out.size() << std::endl;
        std::cout << "same keys? " << mapeqlist(probs_bw_out, OList) << std::endl;

        std::cout << "after byte perm" << std::endl;
        printmap(probs_bw_out);
        //printvec(OList);

        if (round == 2 || round == 4 || round == 6)
        {
            // filter unique values every odd round
            OHash.clear();
            OHash.reserve(OList.size());
            for (state_t val : OList)
                OHash.emplace(val);
            OList.clear();
            for (state_t val : OHash)
                OList.emplace_back(val);
        }

        for (int n = 15; n >= 0; --n)
        {
            //std::cout << "nibble: " << n << std::endl;
            int pos = n^1;
            if (BPmask.getnibble(pos) == 0) continue;
            
            probs_bw_in.swap(probs_bw_out);
            probs_bw_out.clear();

            IList.swap(OList);
            OList.clear();

            std::vector<state_t> used;

            for (const state_t& input : IList){
                state_t val = input;
                /*for (const auto& [key, value] : probs) {
                    if (value == 0) { std::cout << key << "HERE" << std::endl; }
                }*/
                //auto temp_prob = probs_bw.find(temp_input)->second;
                auto input_prob = probs_bw_in[val];
                //std::cout << "temp_prob: " << temp_prob << std::endl;

                //double temp_prob = 1;
                //std::cout << input << std::endl;

                // uses function: bool extcrumbused = partial_grid_permutation(output, pos, BP_mask, extcrumb, control)
                // which modifies output (in place) and returns true if it needed the crumb value and that was outside the BP_mask
                bool extcrumbused = SBTopt::partial_grid_permutation_inv(val, n, BPmask, 0, control);
                state_t output = val.u64 & BPmask.u64;
                //std::cout << "output: " << output << std::endl;
                //OList.push_back(output);

                if (extcrumbused == 0) {
                    probs_bw_out[output] += input_prob;
                    OList.push_back(output);
                    //temp_probs = change_keymap(temp_probs, temp_input, output);
                    //std::cout << "continue" << std::endl;
                    continue;
                }

                OList.push_back(output);
                probs_bw_out[output] += input_prob / 4.;

                //probs_bw[output] += temp_prob/4;
                //std::cout << "BP1 output_size: " << output_probs.size() << std::endl;


                val = input;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 1, control);
                output = val.u64 & BPmask.u64;
                //std::cout << "output: " << output << std::endl;
                OList.push_back(output);
                probs_bw_out[output] += input_prob / 4.;


                //std::cout << "BP2 output_size: " << output_probs.size() << std::endl;
                val = input;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 2, control);
                output = val.u64 & BPmask.u64;
                //std::cout << "output: " << output << std::endl;
                OList.push_back(output);
                probs_bw_out[output] += input_prob / 4.;


                //std::cout << "BP3 output_size: " << output_probs.size() << std::endl;
                val = input;
                SBTopt::partial_grid_permutation_inv(val, n, BPmask, 3, control);
                output = val.u64 & BPmask.u64;
               // std::cout << "output: " << output << std::endl;
                OList.push_back(output);
                probs_bw_out[output] += input_prob / 4.;

                //std::cout << "BP4 output_size: " << output_probs.size() << std::endl;

                /*if (OList.size() == 4) {
                    std::cout << "Here it comes!" << std::endl;
                    printmap(probs_bw);
                    printvec(OList);
                }
                std::cout << "OList size: " << OList.size() << std::endl;*/
                //printmap(probs_bw_out);
                }
            std::cout << "nibble: " << n << std::endl;
            std::cout << "OList size: " << OList.size() << " probs size: " << probs_bw_out.size() << std::endl;
            printvec(OList);
            printmap(probs_bw_out);
        }

        /*for (auto p : output_probs) {
            if (probs_bw.contains(p.first)) {
                probs_bw[p.first] += p.second;
            }
            else {
                probs_bw[p.first] = p.second;
            }

        }*/

        //printmap(output_probs);

        //probs_bw_in.swap(probs_bw_out);
        //probs_bw_out.clear();
        //std::cout << "*****END OF ROUND*****" << std::endl;
        //std::cout << "OList size: " << OList.size() << " probs size: " << probs_bw_out.size() << std::endl;
        //std::cout << "same keys? " << mapeqlist(probs_bw_out, OList) << std::endl;

        //printmap(probs_bw_out);
        //printvec(OList);
        //std::set<state_t> s(OList.begin(), OList.end());
        //OList.assign(s.begin(), s.end());
        //std::cout << "OList unique size: " << s.size() << std::endl;
    }

    std::cout << "Backwards phase done. RESULT: " << std::endl;
    printmap(probs_bw_out);

    std::unordered_set<state_t,state_hash> backwards_list(std::make_move_iterator(OList.begin()),std::make_move_iterator(OList.end()));

    // create forwards list
    IList.clear();
    OList.clear();

   /* std::map<state_t, double> output_probs = probs_bw;
    std::map<state_t, double> input_probs;*/
    //input_probs.clear();
    //output_probs = probs_bw;

    state_t initial_state = original_input;
    SBTopt::bitpermutation(initial_state);
    OList.push_back(initial_state);
    probs_fw_out[initial_state] = 1;

    BPmask = original_BPmask;
    
    //std::cout << "OList size: " << OList.size() << " probs size: " << probs_fw_out.size() << std::endl;
    //std::cout << "same keys? " << mapeqlist(probs_fw_out, OList) << std::endl;

    //output_probs = probs_bw;

    for (int round = 0; round < 4 ; ++round){
        std::cout << "Round " << round << std::endl;
        state_t control = SBTopt::control_Nr_Gr(round, key, original_input);

        std::cout << "OList size: " << OList.size() << " probs size: " << probs_fw_out.size() << std::endl;

        std::cout << "same keys? " << mapeqlist(probs_fw_out, OList) << std::endl;
        // grid permutation
        for (int n = 0; n < 16; ++n)       
        {
            int pos = n^1;
            if (BPmask.getnibble(pos) == 0) continue; 
            
            probs_fw_in.swap(probs_fw_out);
            probs_fw_out.clear();

            IList.swap(OList);
            OList.clear();

            for (const state_t& input : IList){
                state_t val = input;
                auto input_prob = probs_fw_in[input];

                // uses function: bool extcrumbused = partial_grid_permutation(output, pos, BP_mask, extcrumb, control)
                // which modifies output (in place) and returns true if it needed the crumb value and that was outside the BP_mask
                bool extcrumbused = SBTopt::partial_grid_permutation(val, n, BPmask, 0, control);
                state_t output = val.u64 & BPmask.u64;

                if (extcrumbused == 0) {
                    OList.push_back(output);
                    probs_fw_out[output] += input_prob;
                    //temp_probs = change_keymap(temp_probs, temp_input, output);
                    //std::cout << "continue" << std::endl;
                    continue;
                }

                OList.push_back(output);
                probs_fw_out[output] += input_prob / 4.;

                val = input;
                SBTopt::partial_grid_permutation(val, n, BPmask, 1, control);
                output = val.u64 & BPmask.u64;
                OList.push_back(output);
                probs_fw_out[output] += input_prob / 4.;

                val = input;
                SBTopt::partial_grid_permutation(val, n, BPmask, 2, control);
                output = val.u64 & BPmask.u64;
                OList.push_back(output);
                probs_fw_out[output] += input_prob / 4.;

                val = input;
                SBTopt::partial_grid_permutation(val, n, BPmask, 3, control);
                output = val.u64 & BPmask.u64;
                OList.push_back(output);
                probs_fw_out[output] += input_prob / 4.;
                }
        }

        std::cout << "Grid Permutation Done" << std::endl;
        std::cout << "OList size: " << OList.size() << " probs size: " << probs_fw_out.size() << std::endl;
        std::cout << "same keys? " << mapeqlist(probs_fw_out, OList) << std::endl;

        //std::cout << "OList size: " << OList.size() << " probs size: " << probs_fw_in.size() << std::endl;
        //std::cout << "same keys? " << mapeqlist(probs_fw_in, OList) << std::endl;

        if (round == 2 || round == 4 || round == 6)
        {
            // filter unique values every odd round
            OHash.clear();
            OHash.reserve(OList.size());
            for (state_t val : OList)
                OHash.emplace(val);
            OList.clear();
            for (state_t val : OHash)
                OList.emplace_back(val);
        }
        
        //std::cout << "OList size: " << OList.size() << " probs size: " << probs_fw_in.size() << std::endl;
        //std::cout << "same keys? " << mapeqlist(probs_fw_in, OList) << std::endl;
        
        //Byte permutation
        SBTopt::bytepermutation(BPmask);
        
        probs_fw_in.swap(probs_fw_out);
        probs_fw_out.clear();

        IList.swap(OList);
        OList.clear();
        for (state_t input : IList){
            auto input_prob = probs_fw_in[input];
            SBTopt::bytepermutation(input);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output.u64);
            probs_fw_out[output] += input_prob;
        }
        
        //Nibble switch
        IList.swap(OList);
        OList.clear();

        probs_fw_in.swap(probs_fw_out);
        probs_fw_out.clear();

        for (state_t input : IList){
            auto input_prob = probs_fw_in[input];
            SBTopt::nibbleswitch(input, control);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output);
            probs_fw_out[output] += input_prob;
        }
        
        //S boxes
        IList.swap(OList);
        OList.clear();

        probs_fw_in.swap(probs_fw_out);
        probs_fw_out.clear();

        for (state_t input : IList){
            auto input_prob = probs_fw_in[input];
            SBTopt::sbox(input);
            state_t output = input.u64 & BPmask.u64;
            OList.push_back(output);
            probs_fw_out[output] += input_prob;
        }
        
        
        std::cout << "*****END OF ROUND*****" << std::endl;
        std::cout << "OList size: " << OList.size() << " probs size: " << probs_fw_out.size() << std::endl;
        std::cout << "same keys? " << mapeqlist(probs_fw_out, OList) << std::endl;

        //printmap(probs_bw);
        //printvec(OList);
        //std::set<state_t> s(OList.begin(), OList.end());
        //OList.assign(s.begin(), s.end());
        //std::cout << "OList unique size: " << s.size() << std::endl;

    }

    std::cout << "FINAL MAPS" << std::endl;
    //printmap(probs_bw_in);
    printmap(probs_bw_out);
    //printmap(probs_fw_in);
    printmap(probs_fw_out);

    double p = 0;

    /*for (auto fw : probs_fw_out) {
        for (auto bw : probs_bw_out) {
            if (fw.first == bw.first && fw.second != 0 && bw.second != 0) {
                p += fw.second * bw.second;
            }
        }
    }*/
    

    if (1) {
        int weight = hammingweight(key.u64 ^ original_key.u64);
        std::cout << "Key:    " << key << " Probability: " << std::left << std::setw(8) << p << " Hamming distance: " << weight << std::endl;
    }
    
    /*if (myfile.is_open())
    {
        int weight = hammingweight(key.u64 ^ original_key.u64);
        myfile << p << ", " << weight;
        myfile << std::endl;

    }*/

    int weight = hammingweight(key.u64 ^ original_key.u64);
    
    if (weights[weight] >= 0) {
        weights[weight] += p;
    }
    else { weights[weight] = p; }
    
    
   
    for (state_t output : OList){
        if (backwards_list.count(output)>0){
            return true;
        }
    }

    return false;
}

List create_single_list(const int& byte_path_number){
    List list;
    
    //create byte path mask
    list.BPmask.u64 = 0;
    list.BPmask.setbyte(byte_path_number, 255);

    //create keymask
    list.keymask = SBTopt::determine_keymask(list.BPmask);

    //create keylist
    uint64_t z = 0;

    std::map<int, double> weights;
    
    do{
            --z;
            z &= list.keymask.u64;

            if (!check_key_mask(z, list.keymask))
            {continue;}
            
            if (valid_mitm(z, list.BPmask)){
                list.keylist.push_back(z);
            };

    }
    while (z != 0);
    
    return list;
}

List combine_lists(const List& list_a, const List& list_b, std::map<state_t, double> probs){

    List list_c;
    uint64_t z = 0;

    list_c.BPmask = list_a.BPmask.u64|list_b.BPmask.u64;
    list_c.keymask = list_a.keymask.u64|list_b.keymask.u64;

    for (const state_t& partial_key : list_a.keylist) {
        
        do{
            --z;
            z &= list_b.keymask.u64&(~list_a.keymask.u64);
            state_t ext_key = z^partial_key.u64;

            if (!check_key_mask(ext_key, list_c.keymask)){
                continue;
            }

            if (valid_mitm(ext_key, list_c.BPmask)){
                list_c.keylist.push_back(ext_key);
        };
        }while (z != 0); // extend partial_key to all possible extended keys
    };

    return list_c;
}

template<typename T>
void write_vector(const std::string& filename, const std::vector<T>& vec)
{
     std::ofstream f(filename.c_str(), std::ios::binary);
     if (!f) { /* file open error */ ; return ; }
     f.write(reinterpret_cast<const char*>(& vec[0]),
sizeof(T)*vec.size() );
}

template<typename T>
void read_vector(const std::string& filename, std::vector<T>& vec)
{
     std::ifstream f(filename.c_str(), std::ios::binary);
     if (!f) { /* file open error */ ; return ; }
     // get total file length
     f.seekg(0, std::ios_base::end);
     size_t len = f.tellg();
     f.seekg(0, std::ios_base::beg);
     if ((len % sizeof(T)) != 0) { /* output file length is not proper
multiple error */; return ; }
     // resize vector to correct size
     vec.resize(len / sizeof(T));
     // load file into vector
     f.read(reinterpret_cast<char*>(& vec[0]), len );

}

int main(int argc, char** argv){

	po::options_description opts("Command line options");
	opts.add_options()
		("help,h", "Show options") // short option & long option
		("input,i", po::value<std::uint64_t>(&original_input.u64), "Provide input block")
		("key,k", po::value<std::uint64_t>(&original_key.u64), "Provide key (to compute output block)")
		("knownkeybitmask,l", po::value<std::uint64_t>(&key_known_bits_mask.u64)->default_value(0), "Leak key bits to attack")
		("output,o", po::value<std::uint64_t>(&original_output.u64), "Provide output block")
		;
	po::variables_map vm;
	// parse command line
	po::store(po::parse_command_line(argc, argv, opts, false, false), vm);
	// set default values if option was not given, and store arguments in variables
	po::notify(vm);

	if (vm.count("help") || vm.count("input")==0 || vm.count("key")+vm.count("output")==0)
	{
		po::print_options_description({opts}); // add other opts as desired in list
		return 0;
	}
	if (vm.count("output")==0)
	{
	    original_output = SBTopt::SBT_cipher(original_key, original_input);
	}
	std::cout << "Input  :" << original_input << std::endl;
	std::cout << "Output :" << original_output << std::endl;
	std::cout << "Key    :" << original_key << std::endl;
	std::cout << "KeyLeak:" << key_known_bits_mask << std::endl;

    List L1 = create_single_list(7-0);
    List L2 = create_single_list(7-1);
    List L3 = create_single_list(7-2);
    List L4 = create_single_list(7-3);
    List L5 = create_single_list(7-4);
    List L6 = create_single_list(7-5);
    List L7 = create_single_list(7-6);
    List L8 = create_single_list(7-7);

    std::cout << "L1 size: " << L1.keylist.size() << std::endl;
    for (auto w : weights) {
        std::cout << "weight: " << w.first << " probability: " << w.second << std::endl;
    }
    std::cout << "L2 size: " << L2.keylist.size() << std::endl;
    std::cout << "L3 size: " << L3.keylist.size() << std::endl;
    std::cout << "L4 size: " << L4.keylist.size() << std::endl;
    std::cout << "L5 size: " << L5.keylist.size() << std::endl;
    std::cout << "L6 size: " << L6.keylist.size() << std::endl;
    std::cout << "L7 size: " << L7.keylist.size() << std::endl;
    std::cout << "L8 size: " << L8.keylist.size() << std::endl;/*

    List L67 = combine_lists(L6, L7, probs);
    std::cout << "L67 size: " << L67.keylist.size() << std::endl;

    List L167 = combine_lists(L67, L1, probs);
    std::cout << "L167 size: " << L167.keylist.size() << std::endl;

    List L1567 = combine_lists(L167, L5, probs);
    std::cout << "L1567 size: " << L1567.keylist.size() << std::endl;

    List L15678 = combine_lists(L1567, L8, probs);
    std::cout << "L15678 size: " << L15678.keylist.size() << std::endl;

    List L125678 = combine_lists(L15678, L2, probs);
    std::cout << "L125678 size: " << L125678.keylist.size() << std::endl;

    List L1235678 = combine_lists(L125678, L3, probs);
    std::cout << "L1235678 size: " << L1235678.keylist.size() << std::endl;

    List L12345678 = combine_lists(L1235678, L4, probs);
    std::cout << "L12345678 size: " << L12345678.keylist.size() << std::endl;

    std::cout << "Computed key: ";
    printvec(L12345678.keylist);
    std::cout << "Original key: " << original_key << std::endl;*/
    myfile.close();
    return 0;
};